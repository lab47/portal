package portal

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"golang.org/x/crypto/ssh"
)

// Server runs commands for clients authenticated by the SSH user CA.
type Server struct {
	Name, CoordinatorURL, Token   string
	CAFile, Principal, PolicyFile string
	ConfigFile, CAPublicKey       string              // Config path and optional inline CA public key.
	Identities                    map[string][]string // Optional inline account policy.
	RelayURL, Listen              string              // Optional relay URL and UDP bind IP:port.
	Labels                        map[string]string   // Optional inventory metadata advertised at each check-in.
}

// Serve checks in with the coordinator and accepts commands until ctx is canceled.
func (s Server) Serve(ctx context.Context) error {
	var err error
	s, err = s.configured()
	if err != nil {
		return err
	}
	if s.Name == "" || s.CoordinatorURL == "" || s.Token == "" || (s.CAFile == "" && s.CAPublicKey == "") || (s.PolicyFile == "" && s.Identities == nil) {
		return errors.New("server requires name, coordinator URL, token, CA public key or CA file, and identities or policy file")
	}
	var policy policy
	if s.PolicyFile != "" {
		policy, err = loadPolicy(s.PolicyFile)
	} else {
		policy, err = compilePolicy(s.Identities)
	}
	if err != nil {
		return err
	}
	var ca ssh.PublicKey
	if s.CAFile != "" {
		ca, err = LoadCAPublicKey(ctx, s.CAFile)
	} else {
		ca, _, _, _, err = ssh.ParseAuthorizedKey([]byte(s.CAPublicKey))
	}
	if err != nil {
		return err
	}
	mode := relay.ModeDefault()
	if s.RelayURL != "" {
		relayURL, err := netaddr.ParseRelayURL(s.RelayURL)
		if err != nil {
			return err
		}
		mode = relay.ModeCustomURLs(relayURL)
	}
	options := []iroh.Option{iroh.WithALPNs(alpn), iroh.WithRelayMode(mode)}
	if s.Listen != "" {
		bind, err := netip.ParseAddrPort(s.Listen)
		if err != nil {
			return err
		}
		options = append(options, iroh.WithBindAddr(bind))
	}
	ep, err := iroh.Bind(ctx, options...)
	if err != nil {
		return err
	}
	defer ep.Shutdown(context.Background())
	checkIn := func() error {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := ep.Online(requestCtx); err != nil {
			return err
		}
		urls := ep.Addr().RelayURLs()
		if len(urls) == 0 {
			return errors.New("no connected home relay")
		}
		reg := registration{Name: s.Name, EndpointID: ep.ID().String(), RelayURL: urls[0].String(), Labels: s.Labels}
		return register(requestCtx, strings.TrimRight(s.CoordinatorURL, "/"), s.Token, reg)
	}
	if err := checkIn(); err != nil {
		return err
	}
	log.Printf("server %s checked in as %s via relay", s.Name, ep.ID())
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := checkIn(); err != nil {
					log.Printf("check-in failed: %v", err)
				}
			}
		}
	}()
	return serve(ctx, ep, ca, s.Principal, policy)
}
