package revokegpt

import (
	"net/http"
	"time"
)

// DefaultTimeout is the total deadline of one call when WithTimeout is not given.
const DefaultTimeout = 5 * time.Second

// MaxTimeout is the largest accepted timeout.
const MaxTimeout = 60 * time.Second

type config struct {
	timeout    time.Duration
	httpClient *http.Client
}

// Option configures New.
type Option func(*config) error

// WithTimeout sets the total deadline of one call, from the first connect to the last body byte. It must be a
// whole number of milliseconds from 1 ms to 60 s (default 5 s); anything else makes New return an *InputError.
func WithTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d < time.Millisecond || d > MaxTimeout || d%time.Millisecond != 0 {
			return inputError("timeout: must be a whole number of milliseconds from 1 to 60000")
		}
		c.timeout = d
		return nil
	}
}

// WithHTTPClient makes the SDK send through a copy of hc. The copy never follows redirects (its CheckRedirect
// is replaced) and has no cookie jar, whatever hc has. Everything else is kept: Transport, Timeout, and so on.
//
// The SDK's own client ignores the proxy environment variables (HTTP_PROXY and the like), so a secret is never
// sent to a proxy you did not choose. To use a proxy or a custom CA, pass a client built for it. The SDK's
// deadline (WithTimeout) is enforced with a context on the whole exchange; a Timeout on hc applies as well.
//
// A client with a nil Transport uses http.DefaultTransport, which does read the proxy environment variables:
// that is your choice, made by passing it. A Transport that ignores the request context cannot be interrupted:
// the call still returns at the deadline, but the goroutine that is inside your Transport stays there (holding
// the request body, which has the secret) until it returns, so a Transport that can hang for good leaks one
// goroutine per timed-out call.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *config) error {
		if hc == nil {
			return inputError("http client: must not be nil")
		}
		c.httpClient = hc
		return nil
	}
}
