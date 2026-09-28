package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseHTTPFlags(t *testing.T) {
	t.Run("defaults to loopback when only --http is given", func(t *testing.T) {
		got, err := parseHTTPFlags([]string{"--http"})
		if err != nil {
			t.Fatal(err)
		}
		if !got.enabled {
			t.Error("--http did not enable the transport")
		}
		if got.addr != "127.0.0.1:7331" {
			t.Errorf("addr = %q, want the loopback default", got.addr)
		}
		if got.allowAnyHost {
			t.Error("allowAnyHost must default to false")
		}
	})

	t.Run("unknown flag is rejected", func(t *testing.T) {
		if _, err := parseHTTPFlags([]string{"--http", "--nope"}); err == nil {
			t.Error("an unknown serve flag must be reported, not ignored")
		}
	})

	t.Run("--addr without a value is rejected", func(t *testing.T) {
		// Otherwise the next flag, or nothing, is consumed as the address.
		if _, err := parseHTTPFlags([]string{"--http", "--addr"}); err == nil {
			t.Error("--addr with no value must be an error")
		}
	})

	t.Run("no --http means stdio", func(t *testing.T) {
		got, err := parseHTTPFlags(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.enabled {
			t.Error("transport must stay on stdio without --http")
		}
	})
}

// This server can be pointed at third-party hosts, so publishing it on a
// routable interface hands anyone who can reach the port the ability to run
// scans from this machine. The default has to be loopback, and the check has
// to survive the ways an address can look local without being local.
func TestValidateBindRefusesNonLoopback(t *testing.T) {
	refused := []string{
		"0.0.0.0:7331",
		":7331",
		"[::]:7331",
		"192.168.1.10:7331",
		"[::]:7331",
		"10.0.0.5:7331",
		"8.8.8.8:7331",
	}
	for _, addr := range refused {
		if err := validateBind(addr, false); err == nil {
			t.Errorf("validateBind(%q) was allowed, but it is not loopback", addr)
		}
	}
}

func TestValidateBindAllowsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7331", "localhost:7331", "[::1]:7331", "127.0.0.53:9000"} {
		if err := validateBind(addr, false); err != nil {
			t.Errorf("validateBind(%q) refused a loopback address: %v", addr, err)
		}
	}
}

func TestValidateBindOptInAllowsAnything(t *testing.T) {
	if err := validateBind("0.0.0.0:7331", true); err != nil {
		t.Errorf("--allow-remote-bind should permit this: %v", err)
	}
}

func TestValidateBindRejectsMalformedAddress(t *testing.T) {
	if err := validateBind("7331", false); err == nil {
		t.Error("a port with no host must be reported, not guessed at")
	}
}

// Binding to loopback is not sufficient on its own. A page on another origin
// can resolve an attacker-controlled name to 127.0.0.1 and have the browser
// issue the request, which arrives carrying the attacker's Host header. That
// is DNS rebinding, and the Host check is what closes it.
func TestLocalOnlyMiddlewareRejectsForeignHost(t *testing.T) {
	var reached bool
	h := localOnlyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("loopback host is allowed", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7331/mcp", nil)
		req.Host = "127.0.0.1:7331"
		h.ServeHTTP(rec, req)
		if !reached {
			t.Error("a loopback request must reach the handler")
		}
	})

	t.Run("rebinding host is refused", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://evil.example.com/mcp", nil)
		req.Host = "evil.example.com"
		h.ServeHTTP(rec, req)
		if reached {
			t.Error("a non-loopback Host reached the handler; that is the rebinding path")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("missing host is refused", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7331/mcp", nil)
		req.Host = ""
		h.ServeHTTP(rec, req)
		if reached {
			t.Error("a request with no Host header must not reach the handler")
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("ipv6 loopback is allowed", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://[::1]:7331/mcp", nil)
		req.Host = "[::1]:7331"
		h.ServeHTTP(rec, req)
		if !reached {
			t.Error("[::1] is loopback and must be allowed")
		}
	})

	t.Run("a name that merely looks local is refused", func(t *testing.T) {
		// "localhost.evil.example" ends with a loopback-looking prefix but is
		// not loopback, and a substring test would have passed it.
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://localhost.evil.example/mcp", nil)
		req.Host = "localhost.evil.example"
		h.ServeHTTP(rec, req)
		if reached {
			t.Error("a hostname starting with localhost must not be treated as loopback")
		}
	})
}

func TestLocalOnlyMiddlewareErrorTextIsActionable(t *testing.T) {
	h := localOnlyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://evil.example.com/mcp", nil)
	req.Host = "evil.example.com"
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "rebinding") {
		t.Errorf("refusal should explain itself, got %q", rec.Body.String())
	}
}
