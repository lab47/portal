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
	ConfigFile, CAFile, Principal string // Config defaults; optional local certificate trust check.
	User                          string // Optional local account on the server; empty uses the server process's account.
}

// Run returns the remote output and status. A nonzero remote exit is in Result,
// while err reports transport, setup, or protocol failures.
func (c Client) Run(ctx context.Context, argv []string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("client requires name, coordinator URL, key, certificate and command")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	return withClient(c, requestCtx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (Result, error) {
		return runRemote(requestCtx, ep, reg, signer, cert, c.User, argv)
	})
}

func withClient[T any](c Client, ctx context.Context, use func(*iroh.Endpoint, registration, ssh.Signer, *ssh.Certificate) (T, error)) (T, error) {
	var zero T
	var err error
	c, err = c.configured()
	if err != nil {
		return zero, err
	}
	if c.Name == "" || c.CoordinatorURL == "" || c.KeyFile == "" || c.CertFile == "" {
		return zero, errors.New("client requires name, coordinator URL, key and certificate")
	}
	signer, cert, err := loadSigner(c.KeyFile, c.CertFile)
	if err != nil {
		return zero, err
	}
	if c.CAFile != "" {
		ca, err := LoadCAPublicKey(ctx, c.CAFile)
		if err != nil {
			return zero, err
		}
		if err := VerifyUserCertificate(ca, c.Principal, cert); err != nil {
			return zero, err
		}
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
