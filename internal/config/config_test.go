package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigStore_BasicAndAtomic(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "rules.json")

	store, err := NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	cfg := store.Config()
	if cfg.Version != CurrentVersion {
		t.Errorf("got version %d, want %d", cfg.Version, CurrentVersion)
	}
	if cfg.EngineOn {
		t.Errorf("fresh config has EngineOn=true, want false")
	}

	// Mutate to add a rule
	err = store.Mutate(func(c *Config) error {
		c.Rules["curl.exe"] = RuleEntry{Adapter: "Ethernet", DownPolicy: DownPolicyAutomatic}
		return nil
	})
	if err != nil {
		t.Fatalf("Mutate failed: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("rules.json was not created: %v", err)
	}

	// Mutate again to verify .bak creation
	err = store.Mutate(func(c *Config) error {
		c.Rules["powershell.exe"] = RuleEntry{Adapter: "Wi-Fi", DownPolicy: DownPolicyBlock}
		return nil
	})
	if err != nil {
		t.Fatalf("Mutate 2 failed: %v", err)
	}

	bakPath := cfgPath + ".bak"
	if _, err := os.Stat(bakPath); err != nil {
		t.Fatalf(".bak file was not created: %v", err)
	}

	// Reload from new store instance
	store2, err := NewStore(cfgPath)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	cfg2 := store2.Config()
	if len(cfg2.Rules) != 2 {
		t.Errorf("got %d rules, want 2", len(cfg2.Rules))
	}
}

func TestConfigStore_CorruptionFallback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "rules.json")

	store, err := NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	err = store.Mutate(func(c *Config) error {
		c.Settings.MainConnection = "Ethernet"
		return nil
	})
	if err != nil {
		t.Fatalf("Mutate 1 failed: %v", err)
	}

	// Trigger .bak creation
	err = store.Mutate(func(c *Config) error {
		c.Settings.MainDownPolicy = MainDownPolicyBlock
		return nil
	})
	if err != nil {
		t.Fatalf("Mutate 2 failed: %v", err)
	}

	// Corrupt primary file
	if err := os.WriteFile(cfgPath, []byte("{ corrupt json: [}"), 0644); err != nil {
		t.Fatalf("corrupt write failed: %v", err)
	}

	// Reloading should fall back to .bak
	storeRecovered, err := NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore with corrupt primary failed: %v", err)
	}
	cfg := storeRecovered.Config()
	if cfg.Settings.MainConnection != "Ethernet" {
		t.Errorf("fallback did not restore from .bak, got %s", cfg.Settings.MainConnection)
	}

	// Now corrupt .bak as well
	if err := os.WriteFile(cfgPath+".bak", []byte("also corrupt garbage"), 0644); err != nil {
		t.Fatalf("corrupt bak failed: %v", err)
	}

	// Reloading with both corrupt must not crash, should return default config
	storeDefault, err := NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore with both corrupt failed: %v", err)
	}
	cfgDef := storeDefault.Config()
	if cfgDef.Settings.MainConnection != "auto" {
		t.Errorf("expected default auto, got %s", cfgDef.Settings.MainConnection)
	}
}
