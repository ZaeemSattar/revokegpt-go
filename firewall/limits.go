package firewall

// Policy limits (protocol v1, section 18.1). The reference is POLICY_LIMITS in
// packages/protocol/src/policy/limits.ts; the vectors in policy.json pin these numbers.
const (
	maxPolicies         = 100
	maxActionsPerRule   = 8
	maxGlobLength       = 200
	maxWildcards        = 8
	maxHostsPerRule     = 16
	maxMethodsPerRule   = 8
	maxSiteHosts        = 64
	maxBundleBytes      = 65536
	maxServedBytes      = 98304
	maxRawPathBytes     = 8192
	maxRevokedJti       = 1000
	maxSetHeaderValue   = 256
	maxSetHeaderName    = 64
	maxRuleName         = 64
	maxCookieBytes      = 4096
	maxSessionTokenLen  = 4096
	staleGraceSeconds   = 21600
	clockSkewSeconds    = 300
	maxReturnPathLength = 2048
	maxSafeInteger      = 9007199254740991

	policySignatureDomain  = "rg-policy-v1\x00"
	sessionSignatureDomain = "rg-session-v1\x00"

	// Cookie names and attributes (section 18.7).
	CookieSession    = "__Host-rg_s"
	CookieClearance  = "__Host-rg_c"
	CookieReturnPath = "__Host-rg_r"
	cookieAttributes = "HttpOnly; Secure; SameSite=Lax; Path=/"

	// Paths served by the integration itself, before any rule is evaluated.
	PathReturn        = "/__rg/return"
	PathSession       = "/__rg/session"
	returnBodyLimit   = 4096
	returnField       = "rg_clearance"
	sessionInitHeader = "X-RG-Session-Init"
)
