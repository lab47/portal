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

// Server authenticates clients using a user CA, or OpenSSH keys when no CA is configured.
type Server struct {
	Name, CoordinatorURL, Token   string
	CAFile, Principal, PolicyFile string
	ConfigFile, CAPublicKey       string              // Config path and optional inline CA public key.
	Identities                    map[string][]string // Optional inline account policy.
	RelayURL, Listen              string              // Optional relay URL and UDP bind IP:port.
	Labels                        map[string]string   // Optional inventory metadata advertised at each check-in.
	AuthorizedKeysFile            string              // Optional authorized_keys override for the server account, not other target users.
	QueryAuthorizedKeysFile       string              // Additional query/monitor-only keys, without a CA.
}

// Serve checks in with the coordinator and accepts commands until ctx is canceled.
func (s Server) Serve(ctx context.Context) error {
	var err error
	s, err = s.configured()
	if err != nil {
		return err
	}
	if s.Name == "" || s.CoordinatorURL == "" || s.Token == "" || ((s.CAFile != "" || s.CAPublicKey != "") && s.PolicyFile == "" && s.Identities == nil) {
		if s.CAFile == "" && s.CAPublicKey == "" {
			return errors.New("server requires name, coordinator URL and registration token")
		}
		return errors.New("server requires name, coordinator URL, token, CA public key or CA file, and identities or policy file")
	}
	auth, policy, err := s.authentication(ctx)
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
	return serve(ctx, ep, auth, policy)
}

func (s Server) authentication(ctx context.Context) (peerAuthenticator, policy, error) {
	if s.CAFile == "" && s.CAPublicKey == "" {
		if s.PolicyFile != "" || s.Identities != nil || s.Principal != "" {
			return peerAuthenticator{}, nil, errors.New("certificate policy and principal require a configured CA")
		}
		return peerAuthenticator{openSSH: true, keyFile: s.AuthorizedKeysFile, queryKeyFile: s.QueryAuthorizedKeysFile}, nil, nil
	}
	if s.AuthorizedKeysFile != "" || s.QueryAuthorizedKeysFile != "" {
		return peerAuthenticator{}, nil, errors.New("authorized_keys and query_authorized_keys cannot be combined with a CA")
	}
	if (s.CAFile == "" && s.CAPublicKey == "") || (s.PolicyFile == "" && s.Identities == nil) {
		return peerAuthenticator{}, nil, errors.New("server requires CA public key or CA file, and identities or policy file")
	}
	var p policy
	var err error
	if s.PolicyFile != "" {
		p, err = loadPolicy(s.PolicyFile)
	} else {
		p, err = compilePolicy(s.Identities)
	}
	if err != nil {
		return peerAuthenticator{}, nil, err
	}
	var ca ssh.PublicKey
	if s.CAFile != "" {
		ca, err = LoadCAPublicKey(ctx, s.CAFile)
	} else {
		ca, _, _, _, err = ssh.ParseAuthorizedKey([]byte(s.CAPublicKey))
	}
	return peerAuthenticator{ca: ca, principal: s.Principal}, p, err
}
