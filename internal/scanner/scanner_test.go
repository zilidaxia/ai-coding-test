package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"ai-coding-test/internal/config"
)

func TestScanTargetsFindsOllamaFixtures(t *testing.T) {
	fixtures := newFixtureSet(t)
	cfg := config.ScanConfig{
		Ports:       []int{fixtures.HTTP10Port, fixtures.HTTP2Port, fixtures.NegativePort},
		Concurrency: 8,
		Timeout:     500 * time.Millisecond,
		BodyLimit:   4096,
		Insecure:    true,
	}

	assets, err := Scan(context.Background(), cfg, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("len(assets) = %d, want 2", len(assets))
	}

	protocols := []string{assets[0].Protocol, assets[1].Protocol}
	slices.Sort(protocols)
	wantProtocols := []string{"HTTP/1.0", "HTTP/2.0"}
	if !slices.Equal(protocols, wantProtocols) {
		t.Fatalf("protocols = %v, want %v", protocols, wantProtocols)
	}
}

func TestPreferredSchemes(t *testing.T) {
	if got := preferredSchemes(443); !slices.Equal(got, []string{"https", "http"}) {
		t.Fatalf("preferredSchemes(443) = %v, want [https http]", got)
	}
	if got := preferredSchemes(80); !slices.Equal(got, []string{"http", "https"}) {
		t.Fatalf("preferredSchemes(80) = %v, want [http https]", got)
	}
}

func TestScanTargetsIncludesReverseDNSDomains(t *testing.T) {
	fixtures := newFixtureSet(t)
	originalLookup := lookupAddr
	lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		if addr == "127.0.0.1" {
			return []string{"ollama.example."}, nil
		}
		return nil, nil
	}
	t.Cleanup(func() {
		lookupAddr = originalLookup
	})

	cfg := config.ScanConfig{
		Ports:       []int{fixtures.HTTP10Port},
		Concurrency: 4,
		Timeout:     500 * time.Millisecond,
		BodyLimit:   4096,
	}

	assets, err := Scan(context.Background(), cfg, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("len(assets) = %d, want 1", len(assets))
	}
	if !strings.Contains(strings.Join(assets[0].Domain, ","), "ollama.example") {
		t.Fatalf("expected reverse DNS domain in %v", assets[0].Domain)
	}
}

type fixtureSet struct {
	HTTP10Port   int
	HTTP2Port    int
	NegativePort int
}

func newFixtureSet(t *testing.T) fixtureSet {
	t.Helper()

	return fixtureSet{
		HTTP10Port:   newHTTP10OllamaFixture(t),
		HTTP2Port:    newHTTP2OllamaFixture(t),
		NegativePort: newNegativeFixture(t),
	}
}

func newHTTP10OllamaFixture(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
				request, err := http.ReadRequest(bufioReader(c))
				if err != nil {
					return
				}
				path := request.URL.Path

				body := `<html><head><title>Ollama</title></head><body>Ollama</body></html>`
				contentType := "text/html"
				switch path {
				case "/api/tags":
					body = `{"models":[{"name":"llama3"}]}`
					contentType = "application/json"
				case "/api/version":
					body = `{"version":"0.5.7"}`
					contentType = "application/json"
				}

				_, _ = fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", contentType, len(body), body)
			}(conn)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func newHTTP2OllamaFixture(t *testing.T) int {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3.2"}]}`))
			return
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.6.0"}`))
			return
		default:
			_, _ = w.Write([]byte(`<html><head><title>Ollama</title></head><body>Ollama</body></html>`))
		}
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port := mustPort(t, parsed.Hostname(), parsed.Port())
	return port
}

func newNegativeFixture(t *testing.T) int {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><head><title>Welcome</title></head><body>Hello</body></html>")
	}))
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port := mustPort(t, parsed.Hostname(), parsed.Port())
	return port
}

func bufioReader(c net.Conn) *bufio.Reader {
	return bufio.NewReader(c)
}

func mustPort(t *testing.T, host, port string) int {
	t.Helper()

	_ = host
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port %q: %v", port, err)
	}
	return value
}
