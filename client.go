package portal

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// Client queries inventory and runs commands over an authenticated iroh connection.
type Client struct {
	Name, CoordinatorURL string
	KeyFile, CertFile    string
	User                 string // Optional local account on the server; empty uses the server process's account.
}

// Run returns the remote output and status. A nonzero remote exit is in Result,
// while err reports transport, setup, or protocol failures.
func (c Client) Run(ctx context.Context, argv []string) (Result, error) {
	if c.Name == "" || c.CoordinatorURL == "" || c.KeyFile == "" || c.CertFile == "" || len(argv) == 0 {
		return Result{}, errors.New("client requires name, coordinator URL, key, certificate and command")
	}
	signer, cert, err := loadSigner(c.KeyFile, c.CertFile)
	if err != nil {
		return Result{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	reg, err := lookup(requestCtx, strings.TrimRight(c.CoordinatorURL, "/"), c.Name)
	if err != nil {
		return Result{}, err
	}
	relayURL, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || relayURL.URL().Host == "" {
		return Result{}, errors.New("invalid relay URL in inventory")
	}
	ep, err := iroh.Bind(requestCtx, iroh.WithRelayMode(relay.ModeCustomURLs(relayURL)))
	if err != nil {
		return Result{}, err
	}
	defer ep.Shutdown(context.Background())
	if err := ep.Online(requestCtx); err != nil {
		return Result{}, err
	}
	return runRemote(requestCtx, ep, reg, signer, cert, c.User, argv)
}
