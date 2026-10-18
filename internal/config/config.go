package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	CurrentVersion = 2

	DownPolicyAutomatic = "automatic"
	DownPolicyBlock     = "block"

	MainDownPolicyFallback = "fallback"
	MainDownPolicyBlock    = "block"
)

type Settings struct {
	MainConnection     string `json:"main_connection"`      // "auto" or adapter name/guid
	MainConnectionName string `json:"main_connection_name"` // friendly name
	MainConnectionGuid string `json:"main_connection_guid"` // adapter GUID
	MainDownPolicy     string `json:"main_down_policy"`     // "fallback" (default) or "block"
	IPv6               string `json:"ipv6"`                 // "clamp" (default)
}

type RuleEntry struct {
	Adapter     string `json:"adapter"`                // adapter name or "Block"
	AdapterGuid string `json:"adapter_guid,omitempty"` // GUID if matched by identity
	DownPolicy  string `json:"down_policy"`            // "automatic" or "block"
}

type Config struct {
	Version           int                  `json:"version"`
	EngineOn          bool                 `json:"engine_on"`
	InstallingUserSID string               `json:"installing_user_sid,omitempty"`
	Settings          Settings             `json:"settings"`
	Rules             map[string]RuleEntry `json:"rules"`
}

func DefaultConfig() *Config {
	return &Config{
		Version:  CurrentVersion,
		EngineOn: false, // Documented: default OFF on fresh install
		Settings: Settings{
			MainConnection: "auto",
			MainDownPolicy: MainDownPolicyFallback,
			IPv6:           "clamp",
		},
		Rules: make(map[string]RuleEntry),
	}
}

type Store struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
}

func DefaultPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Detour", "rules.json")
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	s := &Store{path: path}
	cfg, err := s.load(path)
	if err != nil {
		return nil, err
	}
	s.cfg = cfg
	return s, nil
}

func (s *Store) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.clone(s.cfg)
}

func (s *Store) Mutate(fn func(cfg *Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := s.clone(s.cfg)
	if err := fn(copied); err != nil {
		return err
	}
	copied.Version = CurrentVersion
	if err := s.save(copied); err != nil {
		return err
	}
	s.cfg = copied
	return nil
}

func (s *Store) load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Also check if .bak exists when primary is missing
			bakPath := path + ".bak"
			if bData, bErr := os.ReadFile(bakPath); bErr == nil {
				var cfg Config
				if jErr := json.Unmarshal(bData, &cfg); jErr == nil {
					return s.migrate(&cfg), nil
				}
			}
			return DefaultConfig(), nil
		}
		return nil, err
	}

	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		// Corrupt rules.json: try fallback to .bak
		fmt.Fprintf(os.Stderr, "detour config: corrupt %s (%v); falling back to .bak\n", path, err)
		bakPath := path + ".bak"
		var bakCfg Config
		var jErr error
		bData, bErr := os.ReadFile(bakPath)
		if bErr == nil {
			bData = bytes.TrimPrefix(bData, []byte("\xef\xbb\xbf"))
			if jErr = json.Unmarshal(bData, &bakCfg); jErr == nil {
				return s.migrate(&bakCfg), nil
			}
			fmt.Fprintf(os.Stderr, "detour config: corrupt .bak %s (%v); starting empty\n", bakPath, jErr)
		} else {
			fmt.Fprintf(os.Stderr, "detour config: cannot read .bak %s (%v); starting empty\n", bakPath, bErr)
		}
		return DefaultConfig(), nil
	}

	return s.migrate(&cfg), nil
}

func (s *Store) migrate(c *Config) *Config {
	if c.Settings.MainConnection == "" {
		c.Settings.MainConnection = "auto"
	}
	if c.Settings.MainDownPolicy == "" {
		c.Settings.MainDownPolicy = MainDownPolicyFallback
	}
	if c.Settings.IPv6 == "" {
		c.Settings.IPv6 = "clamp"
	}
	if c.Rules == nil {
		c.Rules = make(map[string]RuleEntry)
	}
	for k, r := range c.Rules {
		if r.DownPolicy == "" {
			r.DownPolicy = DownPolicyAutomatic
			c.Rules[k] = r
		}
	}
	c.Version = CurrentVersion
	return c
}

func (s *Store) save(c *Config) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", s.path, os.Getpid())
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write temp config %s: %w", tmpPath, err)
	}

	// Flush file to disk before renaming
	if f, err := os.OpenFile(tmpPath, os.O_RDWR, 0644); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}

	// If primary config exists, copy it to .bak first
	bakPath := s.path + ".bak"
	if _, err := os.Stat(s.path); err == nil {
		_ = copyFile(s.path, bakPath)
	}

	// Atomic rename replace on Windows
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace config %s: %w", s.path, err)
	}
	return nil
}

func (s *Store) clone(c *Config) *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	out.Rules = make(map[string]RuleEntry, len(c.Rules))
	for k, v := range c.Rules {
		out.Rules[k] = v
	}
	return &out
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
