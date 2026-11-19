package revokegpt

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ZaeemSattar/revokegpt-go/internal/keys"
)

const redacted = "revokegpt.Client{redacted}"

// secret is a siteverify secret key. Every way of printing or encoding it gives a fixed placeholder.
type secret string

func (secret) String() string               { return "[redacted]" }
func (secret) GoString() string             { return "[redacted]" }
func (secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("[redacted]")) }
func (secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }
func (secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

type core struct {
	secret   secret
	endpoint string
	timeout  time.Duration
	http     *http.Client
}

// Client calls the siteverify endpoint of RevokeGPT. It is safe for concurrent use. Create it with New.
//
// The secret is held in an unexported field and is kept out of every printed or encoded form: fmt (%v, %+v,
// %#v, %s and the rest), log/slog, encoding/json and errors.
type Client struct{ c *core }

var localHTTPHosts = map[string]bool{"localhost": true, "127.0.0.1": true}

var printableASCII = regexp.MustCompile(`\A[ -~]*\z`)

// New creates a client for one secret key and one endpoint.
//
// secret is an `rgsk_` key with a valid checksum (a management key `rgmk_` is refused). endpoint is the full
// siteverify URL, such as "https://api.revokegpt.com/v1/siteverify": `https:`, or `http:` on localhost or
// 127.0.0.1 only; no userinfo, query or fragment; no default. A bad argument returns an *InputError (it matches
// ErrInvalidInput) whose text never includes the value.
func New(secretKey, endpoint string, opts ...Option) (*Client, error) {
	if kind, _, ok := keys.ParseSecret(secretKey); !ok || kind != keys.Secret {
		return nil, inputError("secret key")
	}
	if err := checkEndpoint(endpoint); err != nil {
		return nil, err
	}
	cfg := config{timeout: DefaultTimeout}
	for _, o := range opts {
		if o == nil {
			return nil, inputError("option: must not be nil")
		}
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}
	return &Client{c: &core{secret: secret(secretKey), endpoint: endpoint, timeout: cfg.timeout, http: ownedClient(cfg.httpClient)}}, nil
}

// ownedClient is the client the SDK sends through: a copy of the caller's, or a default one. Neither follows
// redirects, and the default one never reads proxy environment variables.
func ownedClient(given *http.Client) *http.Client {
	if given == nil {
		var t *http.Transport
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			t = dt.Clone()
		} else {
			t = &http.Transport{ForceAttemptHTTP2: true, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
		}
		t.Proxy = nil
		given = &http.Client{Transport: t}
	}
	hc := *given
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Jar = nil
	return &hc
}

// checkEndpoint refuses anything but an absolute https URL (or http on a local host) without userinfo, query or
// fragment. The error never includes the value.
func checkEndpoint(endpoint string) error {
	if strings.ContainsAny(endpoint, "?#") {
		return inputError("endpoint: no query or fragment allowed")
	}
	// Printable ASCII only: parsers disagree about tabs, newlines, backslashes and other characters.
	if !printableASCII.MatchString(endpoint) || strings.ContainsAny(endpoint, " \\") {
		return inputError("endpoint: must be an absolute URL of printable ASCII")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return inputError("endpoint: must be an absolute URL")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return inputError("endpoint: no username or password allowed")
	}
	if p := u.Port(); p != "" {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
			if n > 65535 {
				return inputError("endpoint: must be an absolute URL")
			}
		}
	}
	local := u.Scheme == "http" && localHTTPHosts[strings.ToLower(u.Hostname())]
	if u.Scheme != "https" && !local {
		return inputError("endpoint: must be https (http only for localhost or 127.0.0.1)")
	}
	return nil
}

// String returns a fixed placeholder.
func (Client) String() string { return redacted }

// GoString returns a fixed placeholder (the %#v form).
func (Client) GoString() string { return redacted }

// Format writes a fixed placeholder for every verb, so no fmt form can show the secret.
func (Client) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON encodes a fixed placeholder string, never a field of the client.
func (Client) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText encodes a fixed placeholder.
func (Client) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue returns a fixed placeholder for log/slog.
func (Client) LogValue() slog.Value { return slog.StringValue(redacted) }
