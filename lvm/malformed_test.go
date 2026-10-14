package lvm

import (
	"testing"
	"time"
)

// TestParseConfigMalformedList: a list holding something that is no value —
// a stray `}`, `{` or `=` where a corrupted or crafted metadata text puts
// one — is an error, not an endless loop over the same byte.
func TestParseConfigMalformedList(t *testing.T) {
	for _, text := range []string{
		"vg { a = [ } ] }",
		"vg { a = [ { ] }",
		"vg { a = [ = ] }",
		"vg { a = [ \"x\", } }",
	} {
		done := make(chan error, 1)
		go func() {
			_, _, err := parseConfig(text)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("parseConfig(%q) accepted the text", text)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("parseConfig(%q) did not return", text)
		}
	}
}
