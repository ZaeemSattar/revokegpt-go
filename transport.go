package revokegpt

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
)

// userAgent carries the SDK name and version only: no secret and no host data.
const userAgent = "revokegpt-go/" + Version

// maxResponseBytes is the most a JSON answer may carry. A larger answer is refused, never parsed from a
// truncated read (protocol v1 section 22.1).
const maxResponseBytes = 64 * 1024

var errTransport = errors.New("revokegpt: transport failure")

// request is one POST. The secret is in body (verify, a form) or in bearer (every other call), never in the URL.
type request struct {
	url         string
	contentType string
	body        []byte
	// bearer, when set, is sent as Authorization: Bearer <bearer>.
	bearer string
	accept string
	// errorBody reads the body of an answer that is not a 200 as well (not for a 3xx), to find an error code.
	errorBody bool
	// limit is the most body bytes read.
	limit int64
}

// rawResponse is one answer read in full. Body is nil when none was read (a status whose body is not wanted)
// and for a body over the cap (TooLarge is then set).
type rawResponse struct {
	Status   int
	Header   http.Header
	Body     []byte
	TooLarge bool
}

// do sends one POST and reads the answer. The deadline is a context on the whole exchange, connect to the last
// body byte, and it is enforced even when the http.Client ignores its context: the exchange runs in its own
// goroutine and this function returns when the deadline passes. (A transport that ignores its context leaves
// that goroutine parked until the transport returns.) The error says only that the exchange failed; it never
// carries the request, which holds the secret.
//
// A body is read through io.LimitReader(limit+1), so a hostile endpoint cannot make the SDK buffer more than
// the cap. Redirects are not followed (the client's CheckRedirect stops them), and the answer of a 3xx is
// returned as a status with no body.
func (c *core) do(ctx context.Context, r request) (*rawResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	type answer struct {
		r   *rawResponse
		err error
	}
	done := make(chan answer, 1)
	go func() {
		defer func() {
			if recover() != nil { // a panicking RoundTripper must not take the process down
				done <- answer{nil, errTransport}
			}
		}()
		resp, err := c.roundTrip(ctx, r)
		done <- answer{resp, err}
	}()
	select {
	case a := <-done:
		if a.err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return a.r, a.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *core) roundTrip(ctx context.Context, r request) (*rawResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, strings.NewReader(string(r.body)))
	if err != nil {
		return nil, errTransport
	}
	accept := r.accept
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("Content-Type", r.contentType)
	req.Header.Set("User-Agent", userAgent)
	if r.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	// Naming the encoding turns off Go's transparent gzip, so the cap bounds real bytes (a compressed bomb
	// cannot expand past it); an answer that is encoded anyway is refused below.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errTransport
	}
	defer func() { _ = resp.Body.Close() }()
	out := &rawResponse{Status: resp.StatusCode, Header: resp.Header}
	isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400
	if isRedirect || (resp.StatusCode != http.StatusOK && !r.errorBody) {
		return out, nil
	}
	for _, enc := range resp.Header.Values("Content-Encoding") {
		if e := strings.ToLower(strings.TrimSpace(enc)); e != "" && e != "identity" {
			return nil, errTransport
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, r.limit+1))
	if err != nil {
		return nil, errTransport
	}
	if int64(len(data)) > r.limit {
		out.TooLarge = true
		return out, nil
	}
	out.Body = data
	return out, nil
}
