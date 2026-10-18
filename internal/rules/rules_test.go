package rules

import "testing"

func newSetForTest(t *testing.T, pairs []string) *Set {
	t.Helper()
	s, err := New(pairs)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return s
}

func TestParseBasic(t *testing.T) {
	key, adapter, err := Parse("curl.exe = Ethernet ")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if key != "curl.exe" || adapter != "Ethernet" {
		t.Fatalf("got key=%q adapter=%q", key, adapter)
	}
}

func TestParseRejectsBadRules(t *testing.T) {
	for _, bad := range []string{"curl.exe", "=Wi-Fi", "curl.exe=", "   =   "} {
		if _, _, err := Parse(bad); err == nil {
			t.Fatalf("Parse(%q) should fail", bad)
		}
	}
}

func TestMatchBareNameCaseInsensitive(t *testing.T) {
	s := newSetForTest(t, []string{"curl.exe=Ethernet"})
	got, key := s.Match(`C:\Windows\System32\curl.exe`)
	if got != "Ethernet" || key != "curl.exe" {
		t.Fatalf("got adapter=%q key=%q", got, key)
	}
	if got, _ := s.Match(`D:\Tools\NotCurl.exe`); got != "" {
		t.Fatalf("should not match sibling name, got %q", got)
	}
}

func TestMatchFullPathBeatsBareName(t *testing.T) {
	s := newSetForTest(t, []string{
		"curl.exe=Ethernet",
		"C:\\Program Files\\curl\\curl.exe=Wi-Fi",
	})
	got, key := s.Match(`C:\Program Files\curl\curl.exe`)
	if got != "Wi-Fi" || key != `c:\program files\curl\curl.exe` {
		t.Fatalf("full path must win; got adapter=%q key=%q", got, key)
	}
	if got, _ := s.Match(`C:\Windows\System32\curl.exe`); got != "Ethernet" {
		t.Fatalf("other location falls back to bare-name rule; got %q", got)
	}
}

func TestMatchForwardSlashPath(t *testing.T) {
	s := newSetForTest(t, []string{"C:/Program Files/curl/curl.exe=Wi-Fi"})
	if got, _ := s.Match(`C:\Program Files\curl\curl.exe`); got != "Wi-Fi" {
		t.Fatalf("forward-slash rule must match backslash path; got %q", got)
	}
}

func TestMatchNoRules(t *testing.T) {
	var s *Set
	if got, _ := s.Match("anything.exe"); got != "" {
		t.Fatalf("nil set must not match, got %q", got)
	}
	empty := newSetForTest(t, nil)
	if got, _ := empty.Match("curl.exe"); got != "" {
		t.Fatalf("empty set must not match, got %q", got)
	}
}
