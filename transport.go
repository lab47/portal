package portal

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// ClientTransport keeps warm iroh endpoints/connections for a long-lived client.
// Requests still reload credentials/inventory and authenticate each new stream.
// Close releases the cache; canceling its lifetime context does so automatically.
type ClientTransport struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	peers  map[string]*clientPeer
}

type clientPeer struct {
	ep    *iroh.Endpoint
	conn  *iroh.Conn
	users int
	used  time.Time
	local []netip.AddrPort
}

func NewClientTransport(ctx context.Context) *ClientTransport {
	ctx, cancel := context.WithCancel(ctx)
	t := &ClientTransport{ctx: ctx, cancel: cancel, peers: make(map[string]*clientPeer)}
	context.AfterFunc(ctx, t.Close)
	return t
}

func (t *ClientTransport) Close() {
	t.cancel()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for _, peer := range t.peers {
		peer.conn.CloseWithError(0, "client transport closed")
		peer.ep.Shutdown(context.Background())
	}
	clear(t.peers)
}

func (t *ClientTransport) acquire(ctx context.Context, reg registration) (*iroh.Endpoint, *iroh.Conn, func(), error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.ctx.Err() != nil {
		return nil, nil, nil, errors.New("client transport closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	cacheKey := reg.EndpointID + " " + reg.RelayURL
	peer := t.peers[cacheKey]
	if peer != nil && peer.conn.Context().Err() != nil {
		peer.ep.Shutdown(context.Background())
		delete(t.peers, cacheKey)
		peer = nil
	}
	if peer == nil {
		// Bound idle state without evicting an operation that is still running.
		if len(t.peers) >= 16 {
			var oldest string
			for name, p := range t.peers {
				if p.users == 0 && (oldest == "" || p.used.Before(t.peers[oldest].used)) {
					oldest = name
				}
			}
			if oldest == "" {
				return nil, nil, nil, errors.New("all 16 cached client transports are in use")
			}
			p := t.peers[oldest]
			p.conn.CloseWithError(0, "idle cache eviction")
			p.ep.Shutdown(context.Background())
			delete(t.peers, oldest)
		}
		dialCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(t.ctx, cancel)
		defer cancel()
		defer stop()
		ep, err := bindClientEndpoint(t.ctx, reg)
		if err != nil {
			return nil, nil, nil, err
		}
		local := advertiseLocalInterfaces(ep)
		conn, err := dialEndpoint(dialCtx, ep, reg)
		if err != nil {
			ep.Shutdown(context.Background())
			return nil, nil, nil, err
		}
		peer = &clientPeer{ep: ep, conn: conn, local: local}
		t.peers[cacheKey] = peer
	}
	peer.local = advertiseLocalInterfaces(peer.ep, peer.local)
	peer.users++
	peer.used = time.Now()
	release := func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		peer.users--
		peer.used = time.Now()
	}
	return peer.ep, peer.conn, release, nil
}

func bindClientEndpoint(ctx context.Context, reg registration) (*iroh.Endpoint, error) {
	u, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || u.URL().Host == "" {
		return nil, errors.New("invalid relay URL in inventory")
	}
	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeCustomURLs(u)))
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func dialEndpoint(ctx context.Context, ep *iroh.Endpoint, reg registration) (*iroh.Conn, error) {
	id, err := key.ParseEndpointID(reg.EndpointID)
	if err != nil {
		return nil, err
	}
	u, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || u.URL().Host == "" {
		return nil, errors.New("invalid relay URL in inventory")
	}
	if err := ep.Online(ctx); err != nil {
		return nil, err
	}
	return ep.Connect(ctx, netaddr.NewEndpointAddr(id).WithRelayURL(u), alpn)
}

// Existing protocol tests may provide their own endpoint; production requests
// pass the connection acquired by withClient, so it is not closed per stream.
func remoteConnection(ctx context.Context, ep *iroh.Endpoint, reg registration, existing []*iroh.Conn) (*iroh.Conn, func(), error) {
	if len(existing) != 0 {
		return existing[0], func() {}, nil
	}
	conn, err := dialEndpoint(ctx, ep, reg)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() { conn.CloseWithError(0, "") }, nil
}

func localCandidate(bound netip.AddrPort, ip netip.Addr) bool {
	ip = ip.Unmap()
	return bound.Addr().IsUnspecified() && bound.Port() != 0 && ip.IsGlobalUnicast() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() && ip.Zone() == "" &&
		(!bound.Addr().Is4() || ip.Is4())
}

func advertiseLocalInterfaces(ep *iroh.Endpoint, previous ...[]netip.AddrPort) []netip.AddrPort {
	bound := ep.LocalAddr()
	if !bound.Addr().IsUnspecified() {
		return nil
	} // honor an explicit interface bind
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("iroh local interfaces: %v", err)
		if len(previous) != 0 {
			return previous[0]
		}
		return nil
	}
	current := make(map[netip.AddrPort]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil && localCandidate(bound, prefix.Addr()) {
				current[netip.AddrPortFrom(prefix.Addr().Unmap(), bound.Port())] = true
			}
		}
	}
	// Remove only candidates we advertised, not addresses discovered by QAD.
	if len(previous) != 0 {
		for _, addr := range previous[0] {
			if !current[addr] {
				ep.RemoveExternalAddr(addr)
			}
		}
	}
	addresses := make([]netip.AddrPort, 0, len(current))
	for addr := range current {
		ep.AddExternalAddr(addr)
		addresses = append(addresses, addr)
	}
	return addresses
}

func logNetworkReport(ep *iroh.Endpoint) {
	if report, ok := ep.NetReport(); ok {
		log.Printf("iroh network report: udp_v4=%t udp_v6=%t global_v4=%s global_v6=%s", report.UDPv4, report.UDPv6, report.GlobalV4, report.GlobalV6)
	} else {
		log.Printf("iroh network report: pending (relay online does not imply UDP reachability)")
	}
}

func watchConnectionPaths(ctx context.Context, conn *iroh.Conn) func() {
	ctx, cancel := context.WithCancel(ctx)
	var previous string
	report := func(update []iroh.PathInfo) {
		for _, path := range update {
			if !path.Selected {
				continue
			}
			state := selectedPathDescription(path)
			if state != previous {
				rtt := "unknown"
				if path.HasRTT {
					rtt = path.RTT.String()
				}
				log.Printf("iroh selected path: %s rtt=%s", state, rtt)
				previous = state
			}
		}
	}
	paths, err := conn.WatchPaths(ctx)
	if err != nil {
		cancel()
		return func() {}
	}
	report(conn.Paths())
	go func() {
		for update := range paths {
			report(update)
		}
	}()
	return cancel
}

func selectedPathDescription(path iroh.PathInfo) string {
	kind, addr := "direct", "unknown"
	if path.Relayed {
		kind = "relay"
	}
	if path.HasAddr {
		addr = path.Addr.String()
	}
	return fmt.Sprintf("%s %s validated=%t", kind, addr, path.Validated)
}
