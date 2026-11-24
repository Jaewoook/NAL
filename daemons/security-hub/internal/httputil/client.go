package httputil

import (
	"net/http"
	"time"
)

// NoRedirectClient returns a shallow copy of base (or a fresh http.Client when nil)
// with redirects disabled (returning http.ErrUseLastResponse) and a fallback timeout
// applied whenever base has no positive Timeout configured.
func NoRedirectClient(base *http.Client, fallbackTimeout time.Duration) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	}
	if c.Timeout <= 0 && fallbackTimeout > 0 {
		c.Timeout = fallbackTimeout
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}
