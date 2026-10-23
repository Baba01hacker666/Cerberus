package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Peer struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	PublicKey  string            `json:"public_key"`
	Endpoint   string            `json:"endpoint"`
	MeshIP     string            `json:"mesh_ip"`
	AllowedIPs []string          `json:"allowed_ips"`
	Container  string            `json:"container,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	LastSeen   int64             `json:"last_seen,omitempty"`
	Isolated   bool              `json:"isolated,omitempty"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	Peers map[string]Peer `json:"peers"`
}

func New(dataDir string) *Store {
	s := &Store{path: filepath.Join(dataDir, "peers.json"), Peers: map[string]Peer{}}
	_ = s.Load()
	return s
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var tmp struct {
		Peers map[string]Peer `json:"peers"`
	}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	if tmp.Peers != nil {
		s.Peers = tmp.Peers
	}
	return nil
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Add(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		return fmt.Errorf("peer id required")
	}
	s.Peers[p.ID] = p
	return nil
}

func (s *Store) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Peers, id)
}

func (s *Store) Get(id string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.Peers[id]
	return p, ok
}

func (s *Store) List() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Peer, 0, len(s.Peers))
	for _, p := range s.Peers {
		out = append(out, p)
	}
	return out
}

func (s *Store) Path() string { return s.path }
