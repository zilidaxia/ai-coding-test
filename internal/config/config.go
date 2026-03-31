package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConcurrency = 64
	defaultTimeout     = 3 * time.Second
	defaultBodyLimit   = 16 * 1024
	maxExpandedHosts   = 1 << 16
)

type ScanConfig struct {
	CIDRs       []string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	BodyLimit   int64
	Insecure    bool
	OutputPath  string
}

func ParseCLI(args []string) (ScanConfig, error) {
	if len(args) == 0 {
		return ScanConfig{}, errors.New("expected subcommand, try: scan")
	}

	switch args[0] {
	case "scan":
		return parseScanArgs(args[1:])
	default:
		return ScanConfig{}, fmt.Errorf("unsupported subcommand %q", args[0])
	}
}

func parseScanArgs(args []string) (ScanConfig, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cidrArg string
	var portsArg string
	cfg := ScanConfig{
		Concurrency: defaultConcurrency,
		Timeout:     defaultTimeout,
		BodyLimit:   defaultBodyLimit,
	}

	fs.StringVar(&cidrArg, "cidr", "", "CIDR or comma-separated IP/CIDR list")
	fs.StringVar(&portsArg, "ports", "", "ports, for example 80,443,11434-11436")
	fs.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "concurrent workers")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "request timeout")
	fs.Int64Var(&cfg.BodyLimit, "body-limit", cfg.BodyLimit, "max bytes to keep from response body")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "skip TLS certificate validation")
	fs.StringVar(&cfg.OutputPath, "output", "", "optional output file, defaults to stdout")

	if err := fs.Parse(args); err != nil {
		return ScanConfig{}, err
	}
	if strings.TrimSpace(cidrArg) == "" {
		return ScanConfig{}, errors.New("missing --cidr")
	}
	if strings.TrimSpace(portsArg) == "" {
		return ScanConfig{}, errors.New("missing --ports")
	}

	cfg.CIDRs = splitAndTrim(cidrArg)
	ports, err := ParsePorts(portsArg)
	if err != nil {
		return ScanConfig{}, err
	}
	cfg.Ports = ports

	return cfg, nil
}

func ExpandCIDRs(inputs []string) ([]net.IP, error) {
	var out []net.IP
	seen := make(map[string]struct{})

	// 同时支持单 IP 和 CIDR，输出去重后的主机地址列表。
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if ip := net.ParseIP(input); ip != nil {
			key := ip.String()
			if _, ok := seen[key]; !ok {
				out = append(out, ip)
				seen[key] = struct{}{}
			}
			continue
		}

		ip, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", input, err)
		}
		if err := validateCIDRSize(ipNet); err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", input, err)
		}

		current := cloneIP(ip.Mask(ipNet.Mask))
		for ipNet.Contains(current) {
			if isUsableHost(current, ipNet) {
				key := current.String()
				if _, ok := seen[key]; !ok {
					out = append(out, cloneIP(current))
					seen[key] = struct{}{}
				}
			}
			incrementIP(current)
		}
	}

	return out, nil
}

func ParsePorts(input string) ([]int, error) {
	seen := make(map[int]struct{})
	var ports []int

	// 端口既支持单个值，也支持区间，最终输出有序且去重的结果。
	for _, part := range splitAndTrim(input) {
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for port := start; port <= end; port++ {
				if _, ok := seen[port]; ok {
					continue
				}
				ports = append(ports, port)
				seen[port] = struct{}{}
			}
			continue
		}

		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[port]; ok {
			continue
		}
		ports = append(ports, port)
		seen[port] = struct{}{}
	}

	slices.Sort(ports)
	return ports, nil
}

func splitAndTrim(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parsePort(input string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", input)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range %q", input)
	}
	return port, nil
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func isUsableHost(ip net.IP, ipNet *net.IPNet) bool {
	if ipv4 := ip.To4(); ipv4 != nil {
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && ones <= 30 {
			network := ip.Mask(ipNet.Mask).To4()
			broadcast := cloneIP(network.To4())
			for i := range broadcast {
				broadcast[i] |= ^ipNet.Mask[i]
			}
			return !ip.Equal(network) && !ip.Equal(broadcast)
		}
	}
	return true
}

func validateCIDRSize(ipNet *net.IPNet) error {
	ones, bits := ipNet.Mask.Size()
	if ones < 0 || bits < 0 {
		return errors.New("invalid cidr mask")
	}

	// 为了避免超大网段导致长时间阻塞或内存膨胀，这里限制最大展开主机数。
	if bits-ones > 16 {
		return fmt.Errorf("cidr range too large, host bits must be <= 16")
	}
	return nil
}
