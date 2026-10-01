package portal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CoordinatorConfig is a portable registration bundle: the coordinator's
// public URL and the secret used to register servers with that coordinator.
// It must not be distributed to clients that only need inventory lookup.
type CoordinatorConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func DefaultCoordinatorConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "portal", "coordinator.json"), nil
}

func (c CoordinatorConfig) Validate() error {
	if c.Token == "" {
		return errors.New("coordinator config requires a registration token")
	}
	if u, err := url.Parse(c.URL); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Path, "/register/") {
		return errors.New("coordinator config requires an HTTP(S) URL without credentials")
	}
	if strings.ContainsAny(c.Token, "/\r\n") || c.Token == "." || c.Token == ".." {
		return errors.New("invalid coordinator registration token")
	}
	return nil
}

// RegistrationURL encodes the registration credential for copying to a server.
// The server extracts the token locally; it is not sent in an HTTP request path.
func (c CoordinatorConfig) RegistrationURL() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	u, _ := url.Parse(c.URL)
	escaped := strings.TrimRight(u.EscapedPath(), "/")
	u.Path = strings.TrimRight(u.Path, "/") + "/register/" + c.Token
	u.RawPath = escaped + "/register/" + url.PathEscape(c.Token)
	return u.String(), nil
}

// ParseCoordinatorURL splits an enrollment URL into its base URL and token.
// Errors deliberately never include the credential-bearing input.
func ParseCoordinatorURL(value string) (CoordinatorConfig, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return CoordinatorConfig{}, errors.New("invalid coordinator registration URL")
	}
	path := u.EscapedPath()
	i := strings.LastIndex(path, "/register/")
	if i < 0 {
		return CoordinatorConfig{}, errors.New("coordinator registration URL requires /register/TOKEN")
	}
	token, err := url.PathUnescape(path[i+len("/register/"):])
	if err != nil {
		return CoordinatorConfig{}, errors.New("invalid coordinator registration URL")
	}
	u.Path, err = url.PathUnescape(path[:i])
	if err != nil {
		return CoordinatorConfig{}, errors.New("invalid coordinator registration URL")
	}
	u.RawPath = path[:i]
	c := CoordinatorConfig{URL: u.String(), Token: token}
	if err := c.Validate(); err != nil {
		return CoordinatorConfig{}, err
	}
	return c, nil
}

// LoadCoordinatorConfig permits a missing default file for legacy flag-only
// startup, but an explicit file must exist and every existing file must be valid.
func LoadCoordinatorConfig(path string) (CoordinatorConfig, error) {
	explicit := path != ""
	if !explicit {
		var err error
		path, err = DefaultCoordinatorConfigPath()
		if err != nil {
			return CoordinatorConfig{}, err
		}
	}
	var c CoordinatorConfig
	if err := loadPrivateConfig(path, &c); err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return CoordinatorConfig{}, nil
		}
		return CoordinatorConfig{}, err
	}
	if err := c.Validate(); err != nil {
		return CoordinatorConfig{}, err
	}
	return c, nil
}

// Registration-bearing configs share strict decoding and secret permissions.
func loadPrivateConfig(path string, config any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("config must only be accessible by its owner (chmod 600)")
	}
	if info.Size() > 64*1024 {
		return errors.New("config exceeds 64 KiB")
	}
	dec := json.NewDecoder(io.LimitReader(f, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(config); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("config contains trailing data")
	}
	return nil
}
