package portal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ClientConfig contains paths and endpoints, never private key contents.
type ClientConfig struct {
	Key         string `json:"key"`
	CA          string `json:"ca"`
	Coordinator string `json:"coordinator"`
	Cert        string `json:"cert,omitempty"`
	CAURL       string `json:"ca_url,omitempty"`
	Principal   string `json:"principal,omitempty"`
}

func DefaultClientConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "portal", "config.json"), nil
}

// LoadClientConfig uses the default path when path is empty. A missing default
// is allowed for flag-only clients; a missing explicit path is an error.
// Credential paths in the file are relative to its directory.
func LoadClientConfig(path string) (ClientConfig, error) {
	explicit := path != ""
	if !explicit {
		var err error
		path, err = DefaultClientConfigPath()
		if err != nil {
			return ClientConfig{}, err
		}
	}
	f, err := os.Open(path)
	if !explicit && errors.Is(err, os.ErrNotExist) {
		return ClientConfig{}, nil
	}
	if err != nil {
		return ClientConfig{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ClientConfig{}, err
	}
	if info.Size() > 64*1024 {
		return ClientConfig{}, errors.New("client config exceeds 64 KiB")
	}
	var config ClientConfig
	dec := json.NewDecoder(io.LimitReader(f, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return ClientConfig{}, fmt.Errorf("client config %s: %w", path, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return ClientConfig{}, errors.New("client config contains trailing data")
	}
	for _, field := range []*string{&config.Key, &config.CA, &config.Cert} {
		if field == &config.CA && strings.Contains(*field, "://") {
			continue
		}
		if *field != "" && !filepath.IsAbs(*field) {
			*field = filepath.Join(filepath.Dir(path), *field)
		}
	}
	return config, nil
}

func (c Client) configured() (Client, error) {
	config, err := LoadClientConfig(c.ConfigFile)
	if err != nil {
		return Client{}, err
	}
	for _, pair := range [][2]*string{
		{&c.KeyFile, &config.Key}, {&c.CAFile, &config.CA},
		{&c.CertFile, &config.Cert}, {&c.CoordinatorURL, &config.Coordinator},
		{&c.Principal, &config.Principal},
	} {
		if *pair[0] == "" {
			*pair[0] = *pair[1]
		}
	}
	if c.CertFile == "" && c.KeyFile != "" {
		c.CertFile = c.KeyFile + "-cert.pub"
	}
	if c.Principal == "" {
		c.Principal = "admin"
	}
	return c, nil
}
