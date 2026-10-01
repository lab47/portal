package portal

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/crypto/ssh"
)

// ServerConfig bundles server settings, the registration secret, the trusted
// CA public key (authorized_keys format), and the account authorization policy.
type ServerConfig struct {
	Name        string              `json:"name"`
	Coordinator string              `json:"coordinator"`
	CA          string              `json:"ca"`
	Identities  map[string][]string `json:"identities"`
	Principal   string              `json:"principal,omitempty"`
	Relay       string              `json:"relay,omitempty"`
	Listen      string              `json:"listen,omitempty"`
	Labels      map[string]string   `json:"labels,omitempty"`
}

func DefaultServerConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "portal", "server.json"), nil
}

// Validate checks configuration before saving or opening network listeners.
// Account names are resolved on the server, just as for a standalone policy.
func (c ServerConfig) Validate() error {
	if c.Name == "" || c.CA == "" {
		return errors.New("server config requires name and CA public key")
	}
	if _, err := ParseCoordinatorURL(c.Coordinator); err != nil {
		return err
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.CA)); err != nil {
		return errors.New("server config has an invalid CA public key")
	}
	if _, err := compilePolicy(c.Identities); err != nil {
		return err
	}
	if c.Listen != "" {
		if _, err := netip.ParseAddrPort(c.Listen); err != nil {
			return errors.New("server config has an invalid UDP listen address")
		}
	}
	if c.Relay != "" {
		u, err := netaddr.ParseRelayURL(c.Relay)
		if err != nil || u.URL().Host == "" || (u.URL().Scheme != "https" && u.URL().Scheme != "http") {
			return errors.New("server config has an invalid relay URL")
		}
	}
	for key := range c.Labels {
		if key == "" {
			return errors.New("server config label key must not be empty")
		}
	}
	return nil
}

// LoadServerConfig permits a missing default file for flag-only servers.
// Explicit paths must exist. On Unix, secrets must be owner-only readable.
func LoadServerConfig(path string) (ServerConfig, error) {
	explicit := path != ""
	if !explicit {
		var err error
		path, err = DefaultServerConfigPath()
		if err != nil {
			return ServerConfig{}, err
		}
	}
	var c ServerConfig
	if err := loadPrivateConfig(path, &c); err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return ServerConfig{}, nil
		}
		return ServerConfig{}, err
	}
	if err := c.Validate(); err != nil {
		return ServerConfig{}, err
	}
	return c, nil
}

func (s Server) configured() (Server, error) {
	c, err := LoadServerConfig(s.ConfigFile)
	if err != nil {
		return Server{}, err
	}
	var coordinator CoordinatorConfig
	if c.Coordinator != "" {
		coordinator, err = ParseCoordinatorURL(c.Coordinator)
		if err != nil {
			return Server{}, err
		}
	}
	if strings.Contains(s.CoordinatorURL, "/register/") {
		pair, err := ParseCoordinatorURL(s.CoordinatorURL)
		if err != nil {
			return Server{}, err
		}
		if s.Token != "" && s.Token != pair.Token {
			return Server{}, errors.New("registration URL and explicit token disagree")
		}
		s.CoordinatorURL, s.Token = pair.URL, pair.Token
	}
	if coordinator.URL != "" && s.CoordinatorURL != "" && s.CoordinatorURL != coordinator.URL && s.Token == "" {
		return Server{}, errors.New("overriding coordinator URL requires its registration token")
	}
	for _, pair := range [][2]*string{
		{&s.Name, &c.Name}, {&s.CoordinatorURL, &coordinator.URL},
		{&s.Token, &coordinator.Token}, {&s.Principal, &c.Principal},
		{&s.RelayURL, &c.Relay}, {&s.Listen, &c.Listen},
	} {
		if *pair[0] == "" {
			*pair[0] = *pair[1]
		}
	}
	if s.CAFile == "" && s.CAPublicKey == "" {
		s.CAPublicKey = c.CA
	}
	if s.PolicyFile == "" && s.Identities == nil {
		s.Identities = c.Identities
	}
	if s.Labels == nil {
		s.Labels = c.Labels
	} else {
		labels := make(map[string]string, len(c.Labels)+len(s.Labels))
		for key, value := range c.Labels {
			labels[key] = value
		}
		for key, value := range s.Labels {
			labels[key] = value
		}
		s.Labels = labels
	}
	if s.Principal == "" {
		s.Principal = "admin"
	}
	return s, nil
}
