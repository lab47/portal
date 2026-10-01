package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/lab47/portal"
	"miren.dev/mflags"
)

// All client commands resolve defaults in portal.Client, after parsing flags.
func clientConnectionFlags(fs *mflags.FlagSet) func() portal.Client {
	name := fs.String("name", 0, "", "inventory name")
	coordinator := fs.String("coordinator", 0, "", "coordinator HTTP(S) URL (overrides config)")
	key := fs.String("key", 0, "", "SSH private key file (overrides config)")
	cert := fs.String("cert", 0, "", "SSH user certificate file (default: <key>-cert.pub)")
	config := fs.String("config", 0, "", "client config file (default: user config directory/portal/config.json)")
	ca := fs.String("ca", 0, "", "trusted SSH CA public key file (overrides config)")
	principal := fs.String("principal", 0, "", "expected SSH certificate principal (default: admin)")
	return func() portal.Client {
		return portal.Client{Name: *name, CoordinatorURL: *coordinator, KeyFile: *key, CertFile: *cert, ConfigFile: *config, CAFile: *ca, Principal: *principal}
	}
}

func certificateConfigDefaults(fs *mflags.FlagSet, path string, fields map[string]*string) error {
	config, err := portal.LoadClientConfig(path)
	if err != nil {
		return err
	}
	defaults := map[string]string{"key": config.Key, "cert": config.Cert, "ca": config.CA, "ca-url": config.CAURL, "principal": config.Principal}
	for name, field := range fields {
		if !fs.Lookup(name).HasValue && defaults[name] != "" {
			*field = defaults[name]
		}
	}
	if *fields["cert"] == "" && *fields["key"] != "" {
		*fields["cert"] = *fields["key"] + "-cert.pub"
	}
	return nil
}

func registerConfigCommands(dispatcher *mflags.Dispatcher) {
	fs := mflags.NewFlagSet("config init")
	path := fs.String("config", 0, "", "output config path (default: user config directory/portal/config.json)")
	key := fs.String("key", 0, "", "SSH private key path")
	ca := fs.String("ca", 0, "", "trusted SSH CA public key path")
	coordinator := fs.String("coordinator", 0, "", "coordinator HTTP(S) URL")
	cert := fs.String("cert", 0, "", "SSH certificate path (default: <key>-cert.pub)")
	caURL := fs.String("ca-url", 0, "", "optional CA HTTPS origin for cert request/refresh")
	principal := fs.String("principal", 0, "admin", "expected certificate principal")
	dispatcher.Dispatch("config init", mflags.NewCommand(fs, func(_ *mflags.FlagSet, _ []string) error {
		if *key == "" || *ca == "" || *coordinator == "" || *principal == "" {
			return errors.New("--key, --ca and --coordinator required (principal must not be empty)")
		}
		for _, endpoint := range []string{*coordinator, *caURL} {
			if endpoint == "" {
				continue
			}
			u, err := url.Parse(endpoint)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
				return fmt.Errorf("invalid HTTP(S) endpoint %q", endpoint)
			}
		}
		if *caURL != "" {
			u, _ := url.Parse(*caURL)
			if u.Scheme != "https" {
				return errors.New("CA origin requires HTTPS")
			}
		}
		config := portal.ClientConfig{Key: *key, CA: *ca, Coordinator: *coordinator, Cert: *cert, CAURL: *caURL, Principal: *principal}
		for _, field := range []*string{&config.Key, &config.CA, &config.Cert} {
			if *field != "" {
				absolute, err := filepath.Abs(*field)
				if err != nil {
					return err
				}
				*field = absolute
			}
		}
		output := *path
		if output == "" {
			var err error
			output, err = portal.DefaultClientConfigPath()
			if err != nil {
				return err
			}
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
			return err
		}
		if err := writeNewFile(output, append(data, '\n'), 0600); err != nil {
			return err
		}
		fmt.Printf("Client config written to %s\n", output)
		return nil
	}, mflags.WithUsage("Create client config without overwriting an existing file; stores paths, not secrets")))
}
