package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeCapturesHTTP10(t *testing.T) {
	serverURL := newHTTP10Server(t)

	result, err := ProbeURL(context.Background(), serverURL, Options{BodyLimit: 4096})
	if err != nil {
		t.Fatalf("ProbeURL returned error: %v", err)
	}
	if result.Protocol != "HTTP/1.0" {
		t.Fatalf("Protocol = %q, want HTTP/1.0", result.Protocol)
	}
}

func TestProbeCapturesHTTP2(t *testing.T) {
	server := newHTTP2Server(t)

	result, err := ProbeURL(context.Background(), server.URL, Options{BodyLimit: 4096, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("ProbeURL returned error: %v", err)
	}
	if result.Protocol != "HTTP/2.0" {
		t.Fatalf("Protocol = %q, want HTTP/2.0", result.Protocol)
	}
}

func newHTTP10Server(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				_, _ = fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><head><title>Ollama</title></head></html>")
			}(conn)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
	})

	return "http://" + ln.Addr().String()
}

func newHTTP2Server(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Ollama</title></head><body>Ollama</body></html>"))
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server
}

func Test_readLimit(t *testing.T) {
	got, err := readLimit(io.NopCloser(io.LimitReader(&repeatReader{b: 'a'}, 10)), 4)
	if err != nil {
		t.Fatalf("readLimit returned error: %v", err)
	}
	if got != "aaaa" {
		t.Fatalf("readLimit = %q, want aaaa", got)
	}
}

type repeatReader struct {
	b byte
}

func (r *repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	time.Sleep(1 * time.Millisecond)
	return len(p), nil
}
