package firewall

import "github.com/ZaeemSattar/revokegpt-go/hostname"

// The hostname rules (protocol v1, sections 3 and 18) are the SDK's: one implementation in the core module's public
// hostname package, here under the names this package has always exported.

// CanonicalizeHostname is hostname.Canonicalize.
func CanonicalizeHostname(input string) (string, bool) { return hostname.Canonicalize(input) }

// IsValidHostnamePattern is hostname.IsValidPattern: a canonical exact hostname, or "*." plus a canonical hostname
// with at least two labels whose last label is not numeric.
func IsValidHostnamePattern(p string) bool { return hostname.IsValidPattern(p) }

// hostnameMatches is hostname.Matches: host equals the exact pattern, or is a strict subdomain of a "*." pattern.
func hostnameMatches(host, pattern string) bool { return hostname.Matches(host, pattern) }

// RequestHost is hostname.RequestHost: the Host header with an optional ":port" removed, then canonicalized.
func RequestHost(host string) (string, bool) { return hostname.RequestHost(host) }

// HostMatches is hostname.HostMatches.
func HostMatches(pattern, host string) bool { return hostname.HostMatches(pattern, host) }
