package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// httpTransport holds the settings for the network transport.
type httpTransport struct {
	enabled bool
	addr    string
	// allowAnyHost permits a bind address that is not loopback. It is off by
	// default and has to be named explicitly, because this server can be
	// pointed at third-party hosts: publishing it on a routable interface
	// hands anyone who can reach the port the ability to run scans from this
	// machine, with this machine's credentials and egress address.
	allowAnyHost bool
}

// parseHTTPFlags reads the serve flags. getenv is injected so the parsing is
// testable without mutating process state.
func parseHTTPFlags(args []string) (httpTransport, error) {
	t := httpTransport{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--http":
			t.enabled = true
		case "--addr":
			if i+1 >= len(args) {
				return t, errors.New("--addr needs a value, for example --addr 127.0.0.1:7331")
			}
			i++
			t.addr = args[i]
		case "--allow-remote-bind":
			t.allowAnyHost = true
		default:
			return t, fmt.Errorf("unknown serve flag %q", args[i])
		}
	}
	if t.enabled && t.addr == "" {
		t.addr = "127.0.0.1:7331"
	}
	return t, nil
}

// validateBind refuses a non-loopback bind unless it was explicitly allowed.
//
// The check is on the resolved address rather than the literal string, so
// "0.0.0.0", "::" and a hostname that resolves off-box are all caught. A
// string check alone would pass "localhost:7331" on a host whose /etc/hosts
// maps localhost somewhere else.
func validateBind(addr string, allowAny bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--addr %q is not host:port: %w", addr, err)
	}
	if host == "" {
		if allowAny {
			return nil
		}
		return fmt.Errorf("refusing to bind %q: an empty host means every interface. "+
			"Pass --allow-remote-bind only if you intend to expose this scanner to the network", addr)
	}
	if allowAny {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("refusing to bind %q: this server can scan third-party hosts, so it binds "+
			"to loopback only. Pass --allow-remote-bind if that is genuinely what you want", addr)
	}
	// A name was given. Resolve it and apply the same rule to the result.
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("--addr host %q could not be resolved: %w", host, err)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("refusing to bind %q: %s resolves off-box to %s. "+
				"Pass --allow-remote-bind if that is genuinely what you want", addr, host, a)
		}
	}
	return nil
}

// serveHTTP runs the server on the streamable HTTP transport.
func serveHTTP(s *server.MCPServer, t httpTransport, logger *log.Logger) error {
	if err := validateBind(t.addr, t.allowAnyHost); err != nil {
		return err
	}

	// Stateless mode means each request stands alone. A stateful session would
	// need a session manager and an expiring session store, and the only
	// clients this is aimed at reconnect per call, so the state would be
	// created and abandoned.
	httpSrv := server.NewStreamableHTTPServer(s,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
	)

	handler := localOnlyMiddleware(httpSrv)

	ln, err := net.Listen("tcp", t.addr)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", t.addr, err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// A single nuclei or TLS scan can legitimately hold a request open for
		// minutes, so the write timeout is generous. It is not unbounded: a
		// wedged client should not pin a slot forever.
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	fmt.Fprintf(os.Stderr, "sentinel-x: MCP over HTTP on http://%s/mcp\n", ln.Addr())
	fmt.Fprintf(os.Stderr, "sentinel-x: press Ctrl-C to stop\n")

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Printf("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// localOnlyMiddleware rejects requests whose Host header is not loopback.
//
// This is DNS-rebinding defence. The listener is already bound to loopback, so
// the only remaining way to reach it from a browser is a page on another
// origin resolving an attacker-controlled name to 127.0.0.1. Checking the Host
// header closes that, because such a request arrives carrying the attacker's
// hostname. Requests with no Host header at all are refused too: a real client
// always sends one.
func localOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			http.Error(w, "missing Host header", http.StatusBadRequest)
			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w,
				"this endpoint only accepts loopback Host headers; a request naming another host is a "+
					"DNS rebinding attempt rather than a local client", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
