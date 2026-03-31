package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type Options struct {
	BodyLimit          int64
	InsecureSkipVerify bool
}

type Result struct {
	URL        string
	StatusCode int
	Protocol   string
	Header     http.Header
	Body       string
	Title      string
	TLS        bool
	PeerNames  []string
}

func ProbeURL(ctx context.Context, rawURL string, opts Options) (Result, error) {
	// 这里强制开启 HTTP/2 尝试，并允许通过 InsecureSkipVerify 扫描自签证书目标。
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
		// 测绘阶段保留原始响应，避免被自动跟随跳转后丢失 Location 等线索。
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "ollama-map/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	body, err := readLimit(resp.Body, opts.BodyLimit)
	if err != nil {
		return Result{}, err
	}

	return Result{
		URL:        rawURL,
		StatusCode: resp.StatusCode,
		Protocol:   resp.Proto,
		Header:     resp.Header.Clone(),
		Body:       body,
		Title:      extractTitle(body),
		TLS:        resp.TLS != nil,
		PeerNames:  peerNames(resp.TLS),
	}, nil
}

func readLimit(r io.Reader, limit int64) (string, error) {
	if limit <= 0 {
		limit = 16 * 1024
	}
	data, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func extractTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(stripWhitespace(match[1]))
}

func stripWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func peerNames(state *tls.ConnectionState) []string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	seen := make(map[string]struct{})
	out := make([]string, 0, len(cert.DNSNames)+1)
	for _, name := range cert.DNSNames {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		out = append(out, name)
		seen[name] = struct{}{}
	}

	commonName := strings.TrimSpace(strings.ToLower(cert.Subject.CommonName))
	if commonName != "" {
		if _, ok := seen[commonName]; !ok {
			out = append(out, commonName)
		}
	}

	return out
}
