package portal

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
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
	RelayURL, Listen              string // Optional relay URL and UDP bind IP:port.
}

// Serve checks in with the coordinator and accepts commands until ctx is canceled.
func (s Server) Serve(ctx context.Context) error {
	if s.Name == "" || s.CoordinatorURL == "" || s.Token == "" || s.CAFile == "" || s.Principal == "" || s.PolicyFile == "" {
		return errors.New("server requires name, coordinator URL, token, CA file, principal and policy file")
	}
	policy, err := loadPolicy(s.PolicyFile)
	if err != nil {
		return err
	}
	caData, err := os.ReadFile(s.CAFile)
	if err != nil {
		return err
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(caData)
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
		reg := registration{Name: s.Name, EndpointID: ep.ID().String(), RelayURL: urls[0].String()}
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
