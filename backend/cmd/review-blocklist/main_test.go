package main

import "testing"

func TestFindReferenceCoverUsesDomainSuffixesButNotBareTLD(t *testing.T) {
	reference := map[string]struct{}{
		"doubleclick.net":    {},
		"served.example.org": {},
		"net":                {}, // A bare TLD must never cover every domain beneath it.
	}
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{name: "exact", domain: "served.example.org", want: "served.example.org"},
		{name: "parent wildcard", domain: "googleads.g.doubleclick.net", want: "doubleclick.net"},
		{name: "bare tld is ignored", domain: "some-domain.net", want: ""},
		{name: "not covered", domain: "example.com", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := findReferenceCover(test.domain, reference); got != test.want {
				t.Fatalf("findReferenceCover(%q) = %q, want %q", test.domain, got, test.want)
			}
		})
	}
}

func TestFindInstalledCoverUsesTheSameSuffixSemantics(t *testing.T) {
	installed := map[string]struct{}{"ad.example.com": {}}
	if got := findInstalledCover("cdn.ad.example.com", installed); got != "ad.example.com" {
		t.Fatalf("findInstalledCover returned %q", got)
	}
	if got := findInstalledCover("example.com", installed); got != "" {
		t.Fatalf("findInstalledCover unexpectedly covered parent: %q", got)
	}
}
