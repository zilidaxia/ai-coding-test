package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"ai-coding-test/internal/config"
	"ai-coding-test/internal/fingerprint"
	"ai-coding-test/internal/model"
	"ai-coding-test/internal/probe"
)

var absoluteURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)
var lookupAddr = net.DefaultResolver.LookupAddr

type candidate struct {
	asset model.Asset
	rank  int
}

// Run 是 CLI 的主入口，负责把 CIDR 展开成具体 IP 后交给扫描器处理。
func Run(ctx context.Context, cfg config.ScanConfig) ([]model.Asset, error) {
	ips, err := config.ExpandCIDRs(cfg.CIDRs)
	if err != nil {
		return nil, err
	}
	return Scan(ctx, cfg, ips)
}

// Scan 负责并发扫描一组 IP 与端口，并只返回命中的 Ollama 网站资产。
func Scan(ctx context.Context, cfg config.ScanConfig, ips []net.IP) ([]model.Asset, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.BodyLimit <= 0 {
		cfg.BodyLimit = 16 * 1024
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		assets []model.Asset
	)
	sem := make(chan struct{}, cfg.Concurrency)

	for _, ip := range ips {
		ip := cloneIP(ip)
		for _, port := range cfg.Ports {
			port := port
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				asset, ok := scanEndpoint(ctx, cfg, ip, port)
				if !ok {
					return
				}

				mu.Lock()
				assets = append(assets, asset)
				mu.Unlock()
			}()
		}
	}

	wg.Wait()

	slices.SortFunc(assets, func(a, b model.Asset) int {
		if cmp := strings.Compare(a.IP, b.IP); cmp != 0 {
			return cmp
		}
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})

	return assets, nil
}

func scanEndpoint(ctx context.Context, cfg config.ScanConfig, ip net.IP, port int) (model.Asset, bool) {
	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	// 先做一次轻量 TCP 连接，避免对明显未开放端口继续发 HTTP 请求。
	if !isPortOpen(ctx, address, cfg.Timeout) {
		return model.Asset{}, false
	}

	best := candidate{rank: -1}
	for _, scheme := range preferredSchemes(port) {
		candidate, ok := probeScheme(ctx, cfg, ip, port, scheme)
		if !ok {
			continue
		}
		if candidate.rank > best.rank {
			best = candidate
		}
	}

	if best.rank < 0 {
		return model.Asset{}, false
	}
	return best.asset, true
}

func probeScheme(ctx context.Context, cfg config.ScanConfig, ip net.IP, port int, scheme string) (candidate, bool) {
	host := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	baseURL := fmt.Sprintf("%s://%s", scheme, host)
	opts := probe.Options{
		BodyLimit:          cfg.BodyLimit,
		InsecureSkipVerify: cfg.Insecure,
	}

	// 首页响应负责输出 header/body/title 等网站资产字段。
	homepage, err := probeWithTimeout(ctx, baseURL+"/", cfg.Timeout, opts)
	if err != nil {
		return candidate{}, false
	}

	// API 探测负责增强 Ollama 指纹准确度，避免只靠关键字误报。
	tagsResult, _ := probeWithTimeout(ctx, baseURL+"/api/tags", cfg.Timeout, opts)
	versionResult, _ := probeWithTimeout(ctx, baseURL+"/api/version", cfg.Timeout, opts)

	fingerprintResult := fingerprint.Evaluate(fingerprint.Evidence{
		HomepageBody:   homepage.Body,
		APITagsBody:    tagsResult.Body,
		APIVersionBody: versionResult.Body,
	})
	if !fingerprintResult.Matched {
		return candidate{}, false
	}

	asset := model.Asset{
		IP:          ip.String(),
		Port:        port,
		Scheme:      scheme,
		URL:         homepage.URL,
		Host:        host,
		Domain:      extractDomains(ctx, ip, cfg.Timeout, homepage, tagsResult, versionResult),
		StatusCode:  homepage.StatusCode,
		Protocol:    homepage.Protocol,
		Header:      cloneHeader(homepage.Header),
		Body:        homepage.Body,
		Title:       homepage.Title,
		Fingerprint: slices.Clone(fingerprintResult.Fingerprints),
		Confidence:  fingerprintResult.Confidence,
		TLS:         homepage.TLS,
	}
	if asset.Domain == nil {
		asset.Domain = []string{}
	}
	if asset.Header == nil {
		asset.Header = map[string][]string{}
	}

	return candidate{
		asset: asset,
		rank:  confidenceRank(fingerprintResult.Confidence),
	}, true
}

func probeWithTimeout(parent context.Context, rawURL string, timeout time.Duration, opts probe.Options) (probe.Result, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return probe.ProbeURL(ctx, rawURL, opts)
}

func isPortOpen(ctx context.Context, address string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func extractDomains(ctx context.Context, ip net.IP, timeout time.Duration, results ...probe.Result) []string {
	seen := make(map[string]struct{})
	var domains []string

	// 域名线索主要来自证书、Location 跳转和页面中的绝对 URL。
	for _, name := range reverseDNSDomains(ctx, ip, timeout) {
		appendDomain(&domains, seen, name)
	}
	for _, result := range results {
		for _, name := range result.PeerNames {
			appendDomain(&domains, seen, name)
		}
		for _, location := range result.Header.Values("Location") {
			appendDomain(&domains, seen, domainFromLocation(location))
		}
		for _, raw := range absoluteURLPattern.FindAllString(result.Body, -1) {
			appendDomain(&domains, seen, domainFromLocation(raw))
		}
	}

	slices.Sort(domains)
	return domains
}

// preferredSchemes 根据常见端口给出优先探测顺序，尽量减少明显错误的协议尝试。
func preferredSchemes(port int) []string {
	switch port {
	case 443, 465, 563, 636, 853, 8443, 9443:
		return []string{"https", "http"}
	default:
		return []string{"http", "https"}
	}
}

func appendDomain(domains *[]string, seen map[string]struct{}, raw string) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.Trim(raw, ".")
	if raw == "" {
		return
	}
	if host := stripPort(raw); host != "" {
		raw = host
	}
	if ip := net.ParseIP(raw); ip != nil {
		return
	}
	if !strings.Contains(raw, ".") {
		return
	}
	if _, ok := seen[raw]; ok {
		return
	}
	*domains = append(*domains, raw)
	seen[raw] = struct{}{}
}

func domainFromLocation(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func stripPort(value string) string {
	if strings.HasPrefix(value, "[") {
		host, _, err := net.SplitHostPort(value)
		if err == nil {
			return strings.Trim(host, "[]")
		}
	}
	if strings.Count(value, ":") == 1 && strings.Contains(value, ".") {
		host, _, err := net.SplitHostPort(value)
		if err == nil {
			return host
		}
	}
	return value
}

func cloneHeader(header http.Header) map[string][]string {
	if header == nil {
		return nil
	}
	out := make(map[string][]string, len(header))
	for key, values := range header {
		out[key] = slices.Clone(values)
	}
	return out
}

func reverseDNSDomains(parent context.Context, ip net.IP, timeout time.Duration) []string {
	if ip == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	names, err := lookupAddr(ctx, ip.String())
	if err != nil {
		return nil
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func confidenceRank(confidence string) int {
	switch confidence {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
