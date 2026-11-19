package revokegpt

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNewRefusesBadEndpoints(t *testing.T) {
	secretKey := fixtureSecret(t)
	good := []string{
		"https://api.revokegpt.com/v1/siteverify",
		"https://api.revokegpt.com",
		"http://localhost/v1/siteverify",
		"http://localhost:8080/v1/siteverify",
		"http://127.0.0.1:65535/v1/siteverify",
		"http://LOCALHOST:8080/x",
		"HTTPS://api.revokegpt.com/v1/siteverify",
	}
	bad := []string{
		"", "api.revokegpt.com", "/v1/siteverify", "https://", "https:///x", "https://:443/x",
		"http://api.revokegpt.com/v1/siteverify", "http://127.0.0.2/x", "http://[::1]/x", "http://localhost.evil.test/x",
		"ftp://localhost/x", "file:///etc/passwd", "javascript:alert(1)", "https:api.revokegpt.com",
		"https://user@api.revokegpt.com/x", "https://user:pw@api.revokegpt.com/x", "https://@api.revokegpt.com/x",
		"https://api.revokegpt.com/x?", "https://api.revokegpt.com/x?a=1", "https://api.revokegpt.com/x#", "https://api.revokegpt.com/x#f",
		"https://api.revokegpt.com:99999/x", "https://api.revokegpt.com:0x50/x", "https://api.revokegpt.com:-1/x",
		"https://api.revokegpt.com /x", "https://api.revokegpt.com/\tx", "https://api.revokegpt.com/\nx", "https://api.revokegpt.com\\@evil.test/x",
		"https://api.revokegpt.com/é", "https://exämple.com/x", "https://api.revokegpt.com/\x00", " https://api.revokegpt.com/x",
		"https://api.revokegpt.com/x ", "https://a.com\r\nHost: evil/x", "http://localhost。evil.test/x",
		strings.Repeat("a", 1<<16),
	}
	for _, ep := range good {
		if _, err := New(secretKey, ep); err != nil {
			t.Errorf("%q refused: %v", ep, err)
		}
	}
	for _, ep := range bad {
		_, err := New(secretKey, ep)
		var ie *InputError
		if err == nil || !errors.Is(err, ErrInvalidInput) || !errors.As(err, &ie) {
			t.Errorf("%q accepted or not an input error: %v", ep, err)
			continue
		}
		if ep != "" && len(ep) < 100 && strings.Contains(err.Error(), ep) {
			t.Errorf("%q: the error includes the endpoint: %v", ep, err)
		}
	}
}

func TestNewRefusesBadSecrets(t *testing.T) {
	good := fixtureSecret(t)
	for name, key := range map[string]string{
		"empty":             "",
		"corrupted":         good[:len(good)-1] + "y",
		"management key":    "rgmk" + good[4:],
		"truncated":         good[:len(good)-2],
		"extra":             good + "0",
		"newline":           good + "\n",
		"space":             " " + good,
		"other prefix":      "rgpk_7Hq2LmZ9xK4aRb3Nf8Tw",
		"unicode lookalike": strings.Replace(good, "rgsk", "rgsK", 1),
		"fullwidth digits":  good[:20] + "０" + good[21:],
		"upper prefix":      strings.ToUpper(good[:4]) + good[4:],
	} {
		_, err := New(key, testEndpoint)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTimeoutValues(t *testing.T) {
	key := fixtureSecret(t)
	for d, ok := range map[time.Duration]bool{
		time.Millisecond: true, 5 * time.Second: true, 60 * time.Second: true, 1500 * time.Millisecond: true,
		0: false, -time.Millisecond: false, time.Microsecond: false, 1500 * time.Microsecond: false,
		60*time.Second + time.Millisecond: false, 61 * time.Second: false,
		math.MaxInt64: false, math.MinInt64: false, time.Duration(math.MaxInt64 - 1): false,
	} {
		c, err := New(key, testEndpoint, WithTimeout(d))
		if ok != (err == nil) {
			t.Errorf("%v: %v", d, err)
		}
		if err != nil && (!errors.Is(err, ErrInvalidInput) || c != nil) {
			t.Errorf("%v: %v %v", d, err, c)
		}
		if err == nil && c.c.timeout != d {
			t.Errorf("%v: timeout %v", d, c.c.timeout)
		}
	}
	c, _ := New(key, testEndpoint)
	if c.c.timeout != 5*time.Second {
		t.Fatalf("default %v", c.c.timeout)
	}
	if _, err := New(key, testEndpoint, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a nil option: %v", err)
	}
	if _, err := New(key, testEndpoint, WithHTTPClient(nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a nil client: %v", err)
	}
}

func TestErrors(t *testing.T) {
	e := &Error{Code: "bad-request", Status: 400, RequestID: "req_1"}
	if e.Error() != "revokegpt: bad-request (status 400)" {
		t.Fatal(e.Error())
	}
	wrapped := fmt.Errorf("call: %w", &Error{Code: "unavailable", Status: 503})
	if !IsUnavailable(wrapped) || IsUnavailable(e) || IsUnavailable(nil) || IsUnavailable(errors.New("x")) || IsUnavailable(&Error{Code: "network-error"}) {
		t.Fatal("IsUnavailable")
	}
	n := 30
	r := &Error{Code: "rate-limited", Status: 429, RetryAfterSeconds: &n}
	var got *Error
	if !errors.As(fmt.Errorf("x: %w", r), &got) || *got.RetryAfterSeconds != 30 {
		t.Fatal("errors.As")
	}
	// A code with control characters (it could come from a server) cannot forge a log line.
	if s := (&Error{Code: "a\nb\x00" + strings.Repeat("c", 200)}).Error(); strings.ContainsAny(s, "\n\x00") || len(s) > 100 {
		t.Fatalf("%q", s)
	}
	var ie error = &InputError{What: "timeout"}
	if !errors.Is(ie, ErrInvalidInput) || errors.Is(ie, errors.New("revokegpt: invalid input")) {
		t.Fatal("InputError.Is")
	}
}

func TestVersion(t *testing.T) {
	if !regexp.MustCompile(`\A[0-9]+\.[0-9]+\.[0-9]+\z`).MatchString(Version) {
		t.Fatal(Version)
	}
	if !strings.HasSuffix(userAgent, "/"+Version) || !strings.HasPrefix(userAgent, "revokegpt-go/") {
		t.Fatal(userAgent)
	}
}

// TestThePublicSurfaceIsTheDocumentedOne lists every exported name of the package. A test seam, a runner hook or
// a helper that leaks into the public API fails here.
func TestThePublicSurfaceIsTheDocumentedOne(t *testing.T) {
	want := strings.Fields(`AccountDefenderAssessment AccountRef AccountVerification AccountVerificationResult Address AnnotateInput
		Assessment AssessmentInput Client Client.Annotate Client.CreateAssessment Client.EraseAccount Client.Format
		Client.GoString Client.LogValue Client.MarshalJSON Client.MarshalText Client.String Card CardFields Client.Verify ContainsPANRun DefaultTimeout
		Endpoint ErrInvalidInput Error Error.Error Error.Unwrap ExpectedApp FraudPreventionAssessment GatewayInfo InputError
		InputError.Error InputError.Is IsUnavailable MaxTimeout New Option PhoneFraudAssessment RiskAnalysis
		SMSTollFraudVerdict SiteverifyResult TokenProperties TransactionData TransactionEvent TransactionItem
		TransactionUser UserID UserInfo VerificationEndpointResult VerifyOptions VerifyOutcome Version WithHTTPClient
		WithTimeout`)
	sort.Strings(want)
	if got := publicNames(t); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("public names\n got %v\nwant %v", got, want)
	}
}

func publicNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv == nil {
					names = append(names, d.Name.Name)
					continue
				}
				recv := d.Recv.List[0].Type
				if s, ok := recv.(*ast.StarExpr); ok {
					recv = s.X
				}
				if id, ok := recv.(*ast.Ident); ok && id.IsExported() {
					names = append(names, id.Name+"."+d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							names = append(names, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								names = append(names, n.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}
