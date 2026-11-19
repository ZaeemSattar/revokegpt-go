// Command example runs the firewall in front of an origin as a reverse proxy.
//
//	RG_API_BASE     API origin (default https://api.revokegpt.com)
//	RG_SITE_KEY     rgpk_... (required)
//	RG_SECRET_KEY   rgsk_... (needed for requireToken rules)
//	RG_ORIGIN       the origin to proxy to, e.g. http://127.0.0.1:4611 (required)
//	PORT            listen port (default 8080)
//	RG_SITE_ID      optional site UUID to pin (otherwise pinned from the first verified bundle)
//	RG_BUNDLE_REFRESH_MS  bundle refresh interval in ms (conformance runs)
//	RG_PIN_TEST_KEYS=1  conformance runs only: pin the public TEST bundle key (its seed is public
//	                    in the vector generator) instead of the production placeholders.
//
// The firewall is mounted OUTSIDE any ServeMux: a mux would clean "//" and redirect before the
// firewall saw the raw target.
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	firewall "github.com/ZaeemSattar/revokegpt-go/firewall"
)

func main() {
	originURL := os.Getenv("RG_ORIGIN")
	if originURL == "" {
		log.Fatal("RG_ORIGIN is required")
	}
	target, err := url.Parse(originURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		log.Fatal("RG_ORIGIN must be an http(s) URL")
	}
	cfg := firewall.Config{
		SiteKey:   os.Getenv("RG_SITE_KEY"),
		SecretKey: os.Getenv("RG_SECRET_KEY"),
		APIBase:   os.Getenv("RG_API_BASE"),
		SiteID:    os.Getenv("RG_SITE_ID"),
	}
	if ms, err := strconv.Atoi(os.Getenv("RG_BUNDLE_REFRESH_MS")); err == nil && ms > 0 {
		cfg.RefreshInterval = time.Duration(ms) * time.Millisecond
	}
	if os.Getenv("RG_PIN_TEST_KEYS") == "1" {
		cfg.PinnedKeys = firewall.TestPolicyKeys()
	}
	fw, err := firewall.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Forward the target exactly as received: same path bytes, same query, same Host.
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = pr.In.URL.Path
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           fw.Middleware(proxy),
		ReadHeaderTimeout: 10 * time.Second,
		// Let "OPTIONS *" reach the firewall (it answers 400) instead of net/http answering 200.
		DisableGeneralOptionsHandler: true,
	}
	log.Printf("revokegpt firewall listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
