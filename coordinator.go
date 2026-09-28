package adminhelper

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

type registration struct {
	Name       string    `json:"name"`
	EndpointID string    `json:"endpoint_id"`
	RelayURL   string    `json:"relay_url"`
	Expires    time.Time `json:"expires"`
}

type coordinator struct {
	mu      sync.Mutex
	servers map[string]registration
	token   string
}

// NewCoordinator returns an in-memory inventory handler. Registrations require token.
func NewCoordinator(token string) http.Handler {
	c := &coordinator{servers: make(map[string]registration), token: token}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /servers", c.register)
	mux.HandleFunc("GET /servers/{name}", c.lookup)
	return mux
}

func (c *coordinator) register(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+c.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var reg registration
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&reg); err != nil {
		http.Error(w, "invalid registration", http.StatusBadRequest)
		return
	}
	relayURL, relayErr := netaddr.ParseRelayURL(reg.RelayURL)
	_, idErr := key.ParseEndpointID(reg.EndpointID)
	if reg.Name == "" || strings.Contains(reg.Name, "/") || idErr != nil || relayErr != nil || relayURL.URL().Host == "" || (relayURL.URL().Scheme != "http" && relayURL.URL().Scheme != "https") {
		http.Error(w, "invalid registration", http.StatusBadRequest)
		return
	}
	reg.RelayURL = relayURL.String()
	reg.Expires = time.Now().Add(90 * time.Second)
	c.mu.Lock()
	c.servers[reg.Name] = reg
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (c *coordinator) lookup(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	reg, ok := c.servers[r.PathValue("name")]
	if ok && time.Now().After(reg.Expires) {
		delete(c.servers, reg.Name)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reg)
}
