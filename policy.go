package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
)

// policy maps CA-signed certificate key IDs to local account UIDs.
type policy map[string]map[string]bool

func loadPolicy(path string) (policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, errors.New("policy exceeds 64 KiB")
	}
	var config struct {
		Identities map[string][]string `json:"identities"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid policy: trailing data")
	}
	return compilePolicy(config.Identities)
}

func compilePolicy(identities map[string][]string) (policy, error) {
	if len(identities) == 0 {
		return nil, errors.New("policy requires identities")
	}
	allowed := make(policy, len(identities))
	for identity, names := range identities {
		if identity == "" || len(names) == 0 {
			return nil, errors.New("policy identities must have a nonempty key ID and at least one account")
		}
		uids := make(map[string]bool, len(names))
		for _, name := range names {
			if name == "" {
				return nil, errors.New("policy account name must not be empty")
			}
			account, err := user.Lookup(name)
			if err != nil {
				return nil, fmt.Errorf("policy account %q: %w", name, err)
			}
			if account.Uid == "0" && name != "root" {
				return nil, fmt.Errorf("policy UID 0 must be explicitly named root, not %q", name)
			}
			uids[account.Uid] = true
		}
		allowed[identity] = uids
	}
	return allowed, nil
}

func (p policy) authorize(identity, name string) (*user.User, error) {
	if identity == "" {
		return nil, errors.New("certificate key ID required for authorization")
	}
	uids, ok := p[identity]
	if !ok {
		return nil, errors.New("not authorized for target user")
	}
	var account *user.User
	var err error
	if name == "" {
		account, err = user.Current()
	} else {
		account, err = user.Lookup(name)
	}
	if err != nil {
		return nil, fmt.Errorf("unknown target user %q: %w", name, err)
	}
	if !uids[account.Uid] {
		return nil, errors.New("not authorized for target user")
	}
	return account, nil
}
