package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/lab47/portal"
	"golang.org/x/crypto/ssh"
	"miren.dev/mflags"
)

// All client commands resolve defaults in portal.Client, after parsing flags.
func clientConnectionFlags(fs *mflags.FlagSet) func() portal.Client {
	name := fs.String("name", 0, "", "inventory name")
	coordinator := fs.String("coordinator", 0, "", "coordinator HTTP(S) URL (overrides config)")
	key := fs.String("key", 0, "", "SSH private key file (overrides config)")
	cert := fs.String("cert", 0, "", "SSH user certificate file (default: <key>-cert.pub)")
	config := fs.String("config", 0, "", "client config file (default: user config directory/portal/config.json)")
	ca := fs.String("ca", 0, "", "trusted SSH CA public key file or HTTPS URL (overrides config)")
	principal := fs.String("principal", 0, "", "expected SSH certificate principal (default: admin)")
	caURL := fs.String("ca-url", 0, "", "CA HTTPS origin for automatic certificate renewal (overrides config)")
	refreshToken := fs.String("refresh-token", 0, "", "refresh token file (default: <key>.refresh)")
	return func() portal.Client {
		return portal.Client{Name: *name, CoordinatorURL: *coordinator, KeyFile: *key, CertFile: *cert, ConfigFile: *config, CAFile: *ca, Principal: *principal, CAURL: *caURL, RefreshTokenFile: *refreshToken}
	}
}

func certificateConfigDefaults(fs *mflags.FlagSet, path string, fields map[string]*string) error {
	config, err := portal.LoadClientConfig(path)
	if err != nil {
		return err
	}
	defaults := map[string]string{"key": config.Key, "cert": config.Cert, "ca": config.CA, "ca-url": config.CAURL, "principal": config.Principal, "refresh-token": config.RefreshToken}
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
	ca := fs.String("ca", 0, "", "trusted SSH CA public key path or HTTPS URL")
	coordinator := fs.String("coordinator", 0, "", "coordinator HTTP(S) URL")
	cert := fs.String("cert", 0, "", "SSH certificate path (default: <key>-cert.pub)")
	caURL := fs.String("ca-url", 0, "", "CA HTTPS origin for certificate requests and automatic renewal")
	refreshToken := fs.String("refresh-token", 0, "", "refresh token file (default: <key>.refresh)")
	principal := fs.String("principal", 0, "admin", "expected certificate principal")
	dispatcher.Dispatch("config init", mflags.NewCommand(fs, func(_ *mflags.FlagSet, _ []string) error {
		if *coordinator == "" || (*ca != "" && (*key == "" || *principal == "")) {
			return errors.New("--coordinator required; certificate authentication also requires --key and a nonempty principal")
		}
		if *ca == "" && (*cert != "" || *caURL != "" || *refreshToken != "" || fs.Lookup("principal").HasValue) {
			return errors.New("certificate settings require --ca")
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
		config := portal.ClientConfig{Key: *key, CA: *ca, Coordinator: *coordinator, Cert: *cert, CAURL: *caURL, Principal: *principal, RefreshToken: *refreshToken}
		if *ca == "" {
			config.Principal = ""
		}
		for _, field := range []*string{&config.Key, &config.CA, &config.Cert, &config.RefreshToken} {
			if field == &config.CA && strings.Contains(*field, "://") {
				continue
			}
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

func registerServerInitCommand(dispatcher *mflags.Dispatcher, ctx context.Context) {
	fs := mflags.NewFlagSet("server init")
	path := fs.String("config", 0, "", "output server config path (default: user config directory/portal/server.json)")
	name := fs.String("name", 0, "", "inventory name")
	coordinator := fs.String("coordinator", 0, "", "registration URL including /register/TOKEN")
	ca := fs.String("ca", 0, "", "CA public key file or HTTPS URL to fetch and embed")
	identity := fs.String("identity", 0, "", "certificate identity to authorize")
	principal := fs.String("principal", 0, "admin", "required certificate principal")
	authorizedKeys := fs.String("authorized-keys", 0, "", "authorized_keys override for the server account only, without a CA; other target accounts use their own ~/.ssh/authorized_keys")
	queryAuthorizedKeys := fs.String("query-authorized-keys", 0, "", "additional authorized_keys file for queries and monitors only, never commands (without a CA)")
	var users []string
	fs.StringArrayNoSplitVar(&users, "user", 0, nil, "allowed local account (repeatable; root must be explicit)")
	dispatcher.Dispatch("server init", mflags.NewCommand(fs, func(_ *mflags.FlagSet, _ []string) error {
		if *ca != "" && (*identity == "" || len(users) == 0) {
			return errors.New("--identity and --user are required with --ca")
		}
		config := portal.ServerConfig{
			Name: *name, Coordinator: *coordinator,
		}
		if *queryAuthorizedKeys != "" {
			absolute, err := filepath.Abs(*queryAuthorizedKeys)
			if err != nil {
				return err
			}
			config.QueryAuthorizedKeys = absolute
		}
		if *ca == "" {
			if *identity != "" || len(users) != 0 || fs.Lookup("principal").HasValue {
				return errors.New("certificate identity, user and principal require --ca")
			}
			if *authorizedKeys != "" {
				absolute, err := filepath.Abs(*authorizedKeys)
				if err != nil {
					return err
				}
				config.AuthorizedKeys = absolute
			}
		} else {
			if *authorizedKeys != "" || *queryAuthorizedKeys != "" {
				return errors.New("--authorized-keys and --query-authorized-keys cannot be combined with --ca")
			}
			caKey, err := portal.LoadCAPublicKey(ctx, *ca)
			if err != nil {
				return err
			}
			config.CA = string(ssh.MarshalAuthorizedKey(caKey))
			config.Principal, config.Identities = *principal, map[string][]string{*identity: users}
		}
		if err := config.Validate(); err != nil {
			return err
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		if len(data)+1 > 64*1024 {
			return errors.New("server config exceeds 64 KiB")
		}
		output := *path
		if output == "" {
			output, err = portal.DefaultServerConfigPath()
			if err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
			return err
		}
		if err := writeNewFile(output, append(data, '\n'), 0600); err != nil {
			return err
		}
		fmt.Printf("Server config written to %s. Start with portal server", output)
		if *path != "" {
			fmt.Printf(" --config %q", output)
		}
		fmt.Println()
		return nil
	}, mflags.WithUsage("Bundle token, CA public key and policy in an owner-only server config; never overwrites")))
}

func registerCoordinatorInitCommand(dispatcher *mflags.Dispatcher) {
	fs := mflags.NewFlagSet("coordinator init")
	path := fs.String("config", 0, "", "output coordinator config path (default: user config directory/portal/coordinator.json)")
	url := fs.String("url", 0, "", "public coordinator HTTP(S) URL")
	dispatcher.Dispatch("coordinator init", mflags.NewCommand(fs, func(_ *mflags.FlagSet, _ []string) error {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		config := portal.CoordinatorConfig{URL: *url, Token: fmt.Sprintf("%x", secret)}
		if err := config.Validate(); err != nil {
			return err
		}
		output := *path
		if output == "" {
			var err error
			output, err = portal.DefaultCoordinatorConfigPath()
			if err != nil {
				return err
			}
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		if len(data)+1 > 64*1024 {
			return errors.New("coordinator config exceeds 64 KiB")
		}
		if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
			return err
		}
		if err := writeNewFile(output, append(data, '\n'), 0600); err != nil {
			return err
		}
		registrationURL, err := config.RegistrationURL()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Coordinator config written to %s. Registration URL below is secret; share only with servers.\n", output)
		fmt.Println(registrationURL)
		return nil
	}, mflags.WithUsage("Create coordinator config with a random token and print its copy/paste registration URL")))

	show := mflags.NewFlagSet("coordinator url")
	showPath := show.String("config", 0, "", "coordinator config file (default: user config directory/portal/coordinator.json)")
	dispatcher.Dispatch("coordinator url", mflags.NewCommand(show, func(_ *mflags.FlagSet, _ []string) error {
		config, err := portal.LoadCoordinatorConfig(*showPath)
		if err != nil {
			return err
		}
		registrationURL, err := config.RegistrationURL()
		if err != nil {
			return err
		}
		fmt.Println(registrationURL)
		return nil
	}, mflags.WithUsage("Print the secret registration URL for enrolling servers")))
}
