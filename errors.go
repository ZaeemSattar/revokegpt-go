package revokegpt

import (
	"errors"
	"net/http"
	"strconv"
)

// ErrInvalidInput matches (with errors.Is) every argument error of the SDK: a bad secret, endpoint, option or
// request field. No call that returns it has sent a request.
var ErrInvalidInput = errors.New("revokegpt: invalid input")

// InputError is an argument error. What names the argument in fixed words and never includes its value, which
// may be a secret or carry credentials.
type InputError struct{ What string }

// Error implements error.
func (e *InputError) Error() string {
	if e == nil {
		return "revokegpt: invalid input"
	}
	return "revokegpt: invalid input: " + e.What
}

// Is reports whether target is ErrInvalidInput.
func (e *InputError) Is(target error) bool { return target == ErrInvalidInput }

func inputError(what string) error { return &InputError{What: what} }

// Error is a failed call. Code is a stable code, Status the HTTP status (0 when nothing was answered, as for
// "network-error" and "feature-unavailable"). The text never includes the secret, a token, or anything the server
// sent besides the code.
//
// There is no subclass for HTTP 503: use IsUnavailable.
type Error struct {
	Code      string
	Status    int
	RequestID string
	// RetryAfterSeconds is the Retry-After header as 1 to 6 ASCII digits of seconds, or nil.
	RetryAfterSeconds *int

	// cause is the context error behind a "network-error" that the caller's context or the timeout ended.
	cause error
}

// Unwrap returns the context error (context.Canceled or context.DeadlineExceeded) when the call ended because
// the caller's context or the client's timeout did, so errors.Is can match it; the code stays "network-error".
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return "revokegpt: <nil>"
	}
	return "revokegpt: " + sanitize(e.Code) + " (status " + strconv.Itoa(e.Status) + ")"
}

// IsUnavailable reports whether err is an *Error for HTTP 503: the service could not answer. That is "could not
// check", never "not found".
func IsUnavailable(err error) bool {
	var e *Error
	return errors.As(err, &e) && e != nil && e.Status == http.StatusServiceUnavailable
}

// sanitize keeps a code printable: a code read from a response is already restricted, this is a second guard.
func sanitize(code string) string {
	b := []byte(code)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > 64 {
		b = b[:64]
	}
	return string(b)
}
