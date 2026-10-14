package main

import "testing"

// TestJoinNotes: identify keeps a volume's own note beside the probe result.
func TestJoinNotes(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"no recognised filesystem", "", "no recognised filesystem"},
		{"", "truncated capture", "truncated capture"},
		{"no recognised filesystem", "truncated capture", "no recognised filesystem; truncated capture"},
	}
	for _, c := range cases {
		if got := joinNotes(c.a, c.b); got != c.want {
			t.Errorf("joinNotes(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}
