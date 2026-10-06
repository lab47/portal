package portal

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

func TestLocalCandidate(t *testing.T) {
	for _, tc := range []struct {
		bound, ip string
		want      bool
	}{
		{"[::]:1234", "192.168.1.2", true},
		{"[::]:1234", "fd00::2", true},
		{"0.0.0.0:1234", "10.2.3.4", true},
		{"0.0.0.0:1234", "fd00::2", false},
		{"192.168.1.2:1234", "192.168.1.3", false},
		{"[::]:0", "10.2.3.4", false},
		{"[::]:1234", "127.0.0.1", false},
		{"[::]:1234", "::1", false},
		{"[::]:1234", "169.254.2.3", false},
		{"[::]:1234", "fe80::2%eth0", false},
		{"[::]:1234", "224.0.0.1", false},
	} {
		if got := localCandidate(netip.MustParseAddrPort(tc.bound), netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("%s / %s: %t, want %t", tc.bound, tc.ip, got, tc.want)
		}
	}
}

func TestSelectedPathDescription(t *testing.T) {
	p := iroh.PathInfo{Relayed: true}
	if got := selectedPathDescription(p); got != "relay unknown validated=false" {
		t.Fatal(got)
	}
	p.Relayed, p.Validated, p.HasAddr = false, true, true
	p.Addr = netaddr.IPAddr{Addr: netip.MustParseAddrPort("192.168.1.2:1234")}
	if got := selectedPathDescription(p); got != "direct ip:192.168.1.2:1234 validated=true" {
		t.Fatal(got)
	}
}

func TestClientTransportReuseAndLAN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	relayHTTP := httptest.NewServer(relayserver.New())
	defer relayHTTP.Close()
	u, err := netaddr.ParseRelayURL(relayHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	server, err := iroh.Bind(ctx, iroh.WithALPNs(alpn), iroh.WithRelayMode(relay.ModeCustomURLs(u)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	advertiseLocalInterfaces(server)
	candidates := server.Addr().IPAddrs()
	for _, addr := range candidates {
		if !localCandidate(server.LocalAddr(), addr.Addr()) || addr.Port() != server.LocalAddr().Port() {
			t.Fatalf("invalid default-bound candidate: %s", addr)
		}
	}
	stale := netip.MustParseAddrPort("192.0.2.90:1234")
	other := netip.MustParseAddrPort("192.0.2.91:4321")
	server.AddExternalAddr(stale)
	server.AddExternalAddr(other)
	advertiseLocalInterfaces(server, append(candidates, stale))
	keptOther := false
	for _, addr := range server.Addr().IPAddrs() {
		if addr == stale {
			t.Fatal("stale local candidate retained")
		}
		if addr == other {
			keptOther = true
		}
	}
	if !keptOther {
		t.Fatal("refresh removed an address it did not advertise")
	}
	server.RemoveExternalAddr(other)
	if len(candidates) == 0 {
		// Orbs may have only link-local interfaces. Keep exercising pooling
		// over a real connection without falsely claiming LAN coverage.
		server.AddExternalAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), server.LocalAddr().Port()))
	}
	if err := server.Online(ctx); err != nil {
		t.Fatal(err)
	}
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	go serve(ctx, server, peerAuthenticator{ca: ca.PublicKey(), principal: "admin"}, policy{"operator": {fmt.Sprint(os.Geteuid()): true}})
	reg := registration{EndpointID: server.ID().String(), RelayURL: relayHTTP.URL}
	transport := NewClientTransport(ctx)
	defer transport.Close()
	requestCtx, endRequest := context.WithCancel(ctx)
	ep, conn, release, err := transport.acquire(requestCtx, reg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runRemote(requestCtx, ep, reg, signer, cert, "", []string{"/bin/echo", "first"}, conn)
	if err != nil || result.Output != "first\n" {
		t.Fatalf("first: %+v %v", result, err)
	}
	release()
	endRequest()
	ep2, conn2, release2, err := transport.acquire(ctx, reg)
	if err != nil {
		t.Fatal(err)
	}
	if ep2 != ep || conn2 != conn {
		t.Fatal("successful request did not retain endpoint and connection")
	}
	result, err = runRemote(ctx, ep2, reg, testSigner(t), cert, "", []string{"/bin/echo", "forbidden"}, conn2)
	if err != nil || result.Error != "authentication failed" || result.Output != "" {
		t.Fatalf("later stream skipped authentication: %+v %v", result, err)
	}
	result, err = runRemote(ctx, ep2, reg, signer, cert, "", []string{"/bin/echo", "second"}, conn2)
	if err != nil || result.Output != "second\n" {
		t.Fatalf("second: %+v %v", result, err)
	}
	t.Run("LANUpgrade", func(t *testing.T) {
		if len(candidates) == 0 {
			t.Skip("no usable non-loopback interface")
		}
		// This relay fixture has no QAD service: the upgrade must use the LAN
		// candidates exchanged in-band, with no IP address in registration.
		deadline := time.Now().Add(15 * time.Second)
		direct := false
		for time.Now().Before(deadline) && !direct {
			for _, path := range conn.Paths() {
				if path.Selected && path.Validated && !path.Relayed {
					direct = true
				}
			}
			if !direct {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if !direct {
			t.Fatalf("no default-bound LAN upgrade: %+v", conn.Paths())
		}
	})
	slowCtx, stopSlow := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = runRemote(slowCtx, ep, reg, signer, cert, "", []string{"/bin/sleep", "10"}, conn)
	stopSlow()
	if err == nil {
		t.Fatal("canceled command succeeded")
	}
	result, err = runRemote(ctx, ep, reg, signer, cert, "", []string{"/bin/echo", "after-cancel"}, conn)
	if err != nil || result.Output != "after-cancel\n" {
		t.Fatalf("cancel killed sibling connection: %+v %v", result, err)
	}
	release2()
	conn.CloseWithError(0, "test reconnect")
	_, replacement, release3, err := transport.acquire(ctx, reg)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == conn {
		t.Fatal("closed connection was reused")
	}
	release3()
	transport.Close()
	if replacement.Context().Err() == nil {
		t.Fatal("Close left connection alive")
	}
	if _, _, _, err := transport.acquire(ctx, reg); err == nil {
		t.Fatal("closed cache accepted request")
	}
}

// Opt in because this checks real public relay/QAD reachability, not a local
// fixture. A successful report is not proof of connectivity across two NATs.
func TestPublicQADDiscovery(t *testing.T) {
	if os.Getenv("PORTAL_TEST_PUBLIC_QAD") != "1" {
		t.Skip("set PORTAL_TEST_PUBLIC_QAD=1 to test public QAD")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeDefault()))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(context.Background())
	if err := ep.Online(ctx); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		if report, ok := ep.NetReport(); ok && report.HasUDP() {
			t.Logf("QAD observed addresses: v4=%s v6=%s", report.GlobalV4, report.GlobalV6)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no successful public QAD UDP report within 30s")
}
