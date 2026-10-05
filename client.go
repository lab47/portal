package portal

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"golang.org/x/crypto/ssh"
)

// Client queries inventory and runs commands over an authenticated iroh connection.
type Client struct {
	Name, CoordinatorURL          string
	KeyFile, CertFile             string
	ConfigFile, CAFile, Principal string // Config defaults; a CA selects certificate authentication.
	CAURL, RefreshTokenFile       string // Headless renewal; token defaults to <key>.refresh.
	User                          string // Optional local account on the server; empty uses the server process's account.
}

// Run returns the remote output and status. A nonzero remote exit is in Result,
// while err reports transport, setup, or protocol failures.
func (c Client) Run(ctx context.Context, argv []string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("command required")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	return withClient(c, requestCtx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert ssh.PublicKey) (Result, error) {
		return runRemote(requestCtx, ep, reg, signer, cert, c.User, argv)
	})
}

func withClient[T any](c Client, ctx context.Context, use func(*iroh.Endpoint, registration, ssh.Signer, ssh.PublicKey) (T, error)) (T, error) {
	var zero T
	var err error
	c, err = c.configured()
	if err != nil {
		return zero, err
	}
	if c.Name == "" || c.CoordinatorURL == "" {
		return zero, errors.New("client requires name and coordinator URL")
	}
	if c.CAFile != "" && (c.KeyFile == "" || c.CertFile == "") {
		return zero, errors.New("client requires name, coordinator URL, key and certificate")
	}
	var signer ssh.Signer
	var cert ssh.PublicKey
	if c.CAFile == "" {
		var closeAgent func()
		signer, closeAgent, err = openSSHSigner(ctx, c.KeyFile)
		if err == nil {
			defer closeAgent()
			cert = signer.PublicKey()
		}
	} else {
		signer, cert, err = c.clientSigner(ctx)
	}
	if err != nil {
		return zero, err
	}
	reg, err := lookup(ctx, strings.TrimRight(c.CoordinatorURL, "/"), c.Name)
	if err != nil {
		return zero, err
	}
	relayURL, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || relayURL.URL().Host == "" {
		return zero, errors.New("invalid relay URL in inventory")
	}
	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeCustomURLs(relayURL)))
	if err != nil {
		return zero, err
	}
	defer ep.Shutdown(context.Background())
	if err := ep.Online(ctx); err != nil {
		return zero, err
	}
	return use(ep, reg, signer, cert)
}
