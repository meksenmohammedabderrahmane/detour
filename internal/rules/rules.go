// Package rules parses and matches per-app adapter rules. Pure and unit-tested;
// no Windows calls, so its tests are true unit tests.
package rules

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Rule defines one rule entry.
type Rule struct {
	key         string // normalized key, matched longest-first
	adapter     string
	adapterGuid string
	downPolicy  string // "automatic" or "block"
}

func (r Rule) Key() string         { return r.key }
func (r Rule) Adapter() string     { return r.adapter }
func (r Rule) AdapterGuid() string { return r.adapterGuid }
func (r Rule) DownPolicy() string  { return r.downPolicy }

type Set struct {
	mu    sync.RWMutex
	byKey []Rule
}

// Parse turns a `curl.exe=Wi-Fi`-shaped string into a (key, adapter) pair.
func Parse(s string) (key, adapter string, err error) {
	i := strings.IndexRune(s, '=')
	if i < 0 {
		return "", "", fmt.Errorf("invalid rule %q: want <app>=<adapter>", s)
	}
	key = normalizeKey(strings.TrimSpace(s[:i]))
	adapter = strings.TrimSpace(s[i+1:])
	if key == "" || adapter == "" {
		return "", "", errors.New("rule key and adapter must both be non-empty")
	}
	return key, adapter, nil
}

// New builds a Set from `key=adapter` strings ((nil, []) is allowed => no rules).
func New(pairs []string) (*Set, error) {
	s := &Set{}
	for _, p := range pairs {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		key, adapter, err := Parse(trimmed)
		if err != nil {
			return nil, err
		}
		s.byKey = append(s.byKey, Rule{
			key:        key,
			adapter:    adapter,
			downPolicy: "automatic",
		})
	}
	s.sortLocked()
	return s, nil
}

func (s *Set) sortLocked() {
	sort.Slice(s.byKey, func(i, j int) bool {
		return len(s.byKey[i].key) > len(s.byKey[j].key)
	})
}

// SetRule adds or updates a rule.
func (s *Set) SetRule(key, adapter, adapterGuid, downPolicy string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	norm := normalizeKey(key)
	if downPolicy == "" {
		downPolicy = "automatic"
	}

	found := false
	for i := range s.byKey {
		if s.byKey[i].key == norm {
			s.byKey[i].adapter = adapter
			s.byKey[i].adapterGuid = adapterGuid
			s.byKey[i].downPolicy = downPolicy
			found = true
			break
		}
	}
	if !found {
		s.byKey = append(s.byKey, Rule{
			key:         norm,
			adapter:     adapter,
			adapterGuid: adapterGuid,
			downPolicy:  downPolicy,
		})
	}
	s.sortLocked()
}

// Delete removes a rule by key.
func (s *Set) Delete(key string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	norm := normalizeKey(key)
	for i := range s.byKey {
		if s.byKey[i].key == norm {
			s.byKey = append(s.byKey[:i], s.byKey[i+1:]...)
			return true
		}
	}
	return false
}

// Lookup finds a matching rule for exePath.
func (s *Set) Lookup(exePath string) (Rule, bool) {
	if s == nil || exePath == "" {
		return Rule{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	norm := normalizeKey(cleanPath(exePath))
	for _, r := range s.byKey {
		if norm == r.key || strings.HasSuffix(norm, "\\"+r.key) {
			return r, true
		}
	}
	return Rule{}, false
}

// Match returns the adapter for an exe path, or "" when no rule applies.
func (s *Set) Match(exePath string) (adapter, key string) {
	if r, ok := s.Lookup(exePath); ok {
		return r.adapter, r.key
	}
	return "", ""
}

// List returns the rules ordered longest-first.
func (s *Set) List() []Rule {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Rule(nil), s.byKey...)
}

func normalizeKey(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "/", "\\")
}

func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `\\?\`)
	return s
}
