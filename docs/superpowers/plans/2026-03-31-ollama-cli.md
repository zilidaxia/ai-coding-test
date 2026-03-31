# Ollama CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go CLI that scans an IP/CIDR plus port range, identifies Ollama web assets, and outputs structured JSONL records including protocol, headers, body, host, and discovered domains.

**Architecture:** The CLI expands targets into `(ip, port)` jobs, probes each target over HTTP and HTTPS, collects homepage and API evidence, scores an Ollama fingerprint, and streams matched records as JSONL. Integration tests use local HTTP/1.0 and HTTP/2.0 fixtures to verify protocol-aware detection and dataset output.

**Tech Stack:** Go standard library (`flag`, `net`, `net/http`, `httptest`, `encoding/json`, `crypto/tls`)

---

### Task 1: Bootstrap Module And Input Parsing

**Files:**
- Create: `go.mod`
- Create: `main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests for CIDR and port parsing**

```go
func TestParseCIDRsSingleIPAndCIDR(t *testing.T) {
    targets, err := ExpandCIDRs([]string{"127.0.0.1", "192.168.1.0/30"})
    if err != nil {
        t.Fatalf("ExpandCIDRs returned error: %v", err)
    }
    got := make([]string, 0, len(targets))
    for _, ip := range targets {
        got = append(got, ip.String())
    }
    want := []string{"127.0.0.1", "192.168.1.1", "192.168.1.2"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("ExpandCIDRs = %v, want %v", got, want)
    }
}

func TestParsePortsMergesSinglesAndRanges(t *testing.T) {
    got, err := ParsePorts("80,443,11434-11436")
    if err != nil {
        t.Fatalf("ParsePorts returned error: %v", err)
    }
    want := []int{80, 443, 11434, 11435, 11436}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("ParsePorts = %v, want %v", got, want)
    }
}
```

- [ ] **Step 2: Run the parsing tests to verify they fail**

Run: `go test ./internal/config -run 'TestParseCIDRsSingleIPAndCIDR|TestParsePortsMergesSinglesAndRanges'`
Expected: FAIL because parsing functions do not exist yet

- [ ] **Step 3: Write minimal parsing implementation and CLI config**

```go
type ScanConfig struct {
    CIDRs       []string
    Ports       []int
    Concurrency int
    Timeout     time.Duration
    BodyLimit   int64
    Insecure    bool
    OutputPath  string
}
```

- [ ] **Step 4: Run the parsing tests to verify they pass**

Run: `go test ./internal/config -run 'TestParseCIDRsSingleIPAndCIDR|TestParsePortsMergesSinglesAndRanges'`
Expected: PASS

### Task 2: Define Asset Model And JSONL Output

**Files:**
- Create: `internal/model/asset.go`
- Create: `internal/output/jsonl.go`
- Create: `internal/output/jsonl_test.go`

- [ ] **Step 1: Write the failing JSONL serialization test**

```go
func TestWriteJSONL(t *testing.T) {
    buf := new(bytes.Buffer)
    err := WriteJSONL(buf, []model.Asset{
        {
            IP:       "127.0.0.1",
            Port:     11434,
            Host:     "127.0.0.1:11434",
            Domain:   []string{"ollama.local"},
            Protocol: "HTTP/2.0",
        },
    })
    if err != nil {
        t.Fatalf("WriteJSONL returned error: %v", err)
    }
    got := strings.TrimSpace(buf.String())
    if !strings.Contains(got, "\"protocol\":\"HTTP/2.0\"") {
        t.Fatalf("output missing protocol field: %s", got)
    }
}
```

- [ ] **Step 2: Run the JSONL test to verify it fails**

Run: `go test ./internal/output -run TestWriteJSONL`
Expected: FAIL because asset model and writer do not exist yet

- [ ] **Step 3: Write minimal asset model and JSONL writer**

```go
type Asset struct {
    IP         string              `json:"ip"`
    Port       int                 `json:"port"`
    Scheme     string              `json:"scheme,omitempty"`
    URL        string              `json:"url,omitempty"`
    Host       string              `json:"host"`
    Domain     []string            `json:"domain"`
    StatusCode int                 `json:"status_code,omitempty"`
    Protocol   string              `json:"protocol,omitempty"`
    Header     map[string][]string `json:"header"`
    Body       string              `json:"body"`
    Title      string              `json:"title,omitempty"`
    Fingerprint []string           `json:"fingerprint,omitempty"`
    Confidence string              `json:"confidence,omitempty"`
    TLS        bool                `json:"tls"`
}
```

- [ ] **Step 4: Run the JSONL test to verify it passes**

Run: `go test ./internal/output -run TestWriteJSONL`
Expected: PASS

### Task 3: Implement Fingerprint Evaluation

**Files:**
- Create: `internal/fingerprint/ollama.go`
- Create: `internal/fingerprint/ollama_test.go`

- [ ] **Step 1: Write the failing fingerprint tests**

```go
func TestEvaluateHighConfidenceFromAPIs(t *testing.T) {
    result := Evaluate(Evidence{
        HomepageBody: `{"models":[{"name":"llama3"}]}`,
        APITagsBody:  `{"models":[{"name":"llama3"}]}`,
        APIVersionBody: `{"version":"0.5.7"}`,
    })
    if result.Confidence != "high" {
        t.Fatalf("Confidence = %q, want high", result.Confidence)
    }
}

func TestEvaluateRejectsGenericPage(t *testing.T) {
    result := Evaluate(Evidence{
        HomepageBody: "<html><title>Welcome</title></html>",
    })
    if result.Matched {
        t.Fatalf("Expected generic page not to match")
    }
}
```

- [ ] **Step 2: Run the fingerprint tests to verify they fail**

Run: `go test ./internal/fingerprint -run 'TestEvaluateHighConfidenceFromAPIs|TestEvaluateRejectsGenericPage'`
Expected: FAIL because evaluator does not exist yet

- [ ] **Step 3: Write minimal fingerprint evaluator**

```go
type Evidence struct {
    HomepageBody   string
    APITagsBody    string
    APIVersionBody string
}

type Result struct {
    Matched      bool
    Fingerprints []string
    Confidence   string
}
```

- [ ] **Step 4: Run the fingerprint tests to verify they pass**

Run: `go test ./internal/fingerprint -run 'TestEvaluateHighConfidenceFromAPIs|TestEvaluateRejectsGenericPage'`
Expected: PASS

### Task 4: Implement Protocol-Aware HTTP Prober

**Files:**
- Create: `internal/probe/http.go`
- Create: `internal/probe/http_test.go`

- [ ] **Step 1: Write the failing protocol probe tests**

```go
func TestProbeCapturesHTTP10(t *testing.T) {
    server := newHTTP10Server(t)
    result, err := ProbeURL(context.Background(), server.URL, Options{BodyLimit: 4096})
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
```

- [ ] **Step 2: Run the protocol probe tests to verify they fail**

Run: `go test ./internal/probe -run 'TestProbeCapturesHTTP10|TestProbeCapturesHTTP2'`
Expected: FAIL because probe implementation does not exist yet

- [ ] **Step 3: Write minimal HTTP probe implementation**

```go
type Result struct {
    URL        string
    StatusCode int
    Protocol   string
    Header     http.Header
    Body       string
    Title      string
    TLS        bool
}
```

- [ ] **Step 4: Run the protocol probe tests to verify they pass**

Run: `go test ./internal/probe -run 'TestProbeCapturesHTTP10|TestProbeCapturesHTTP2'`
Expected: PASS

### Task 5: Implement Scanner Composition

**Files:**
- Create: `internal/scanner/scanner.go`
- Create: `internal/scanner/scanner_test.go`

- [ ] **Step 1: Write the failing scanner integration test**

```go
func TestScanTargetsFindsOllamaFixtures(t *testing.T) {
    fixtures := newFixtureSet(t)
    cfg := ScanConfig{
        Ports: []int{fixtures.HTTP10Port, fixtures.HTTP2Port, fixtures.NegativePort},
    }
    assets, err := Scan(context.Background(), cfg, []net.IP{net.ParseIP("127.0.0.1")})
    if err != nil {
        t.Fatalf("Scan returned error: %v", err)
    }
    if len(assets) != 2 {
        t.Fatalf("len(assets) = %d, want 2", len(assets))
    }
}
```

- [ ] **Step 2: Run the scanner test to verify it fails**

Run: `go test ./internal/scanner -run TestScanTargetsFindsOllamaFixtures`
Expected: FAIL because scanner composition does not exist yet

- [ ] **Step 3: Write minimal scanner composition**

```go
func Scan(ctx context.Context, cfg config.ScanConfig, ips []net.IP) ([]model.Asset, error) {
    // expand (ip, port) jobs
    // probe homepage and Ollama API paths
    // evaluate fingerprint
    // return matched assets
}
```

- [ ] **Step 4: Run the scanner test to verify it passes**

Run: `go test ./internal/scanner -run TestScanTargetsFindsOllamaFixtures`
Expected: PASS

### Task 6: Wire CLI Command And Sample Dataset

**Files:**
- Modify: `main.go`
- Create: `testdata/dataset/expected-assets.jsonl`
- Create: `internal/scanner/dataset_test.go`

- [ ] **Step 1: Write the failing dataset output test**

```go
func TestDatasetOutputContainsHTTP10AndHTTP2(t *testing.T) {
    got := generateDatasetOutput(t)
    if !strings.Contains(got, `"protocol":"HTTP/1.0"`) {
        t.Fatalf("dataset output missing HTTP/1.0 Ollama asset: %s", got)
    }
    if !strings.Contains(got, `"protocol":"HTTP/2.0"`) {
        t.Fatalf("dataset output missing HTTP/2.0 Ollama asset: %s", got)
    }
}
```

- [ ] **Step 2: Run the dataset test to verify it fails**

Run: `go test ./internal/scanner -run TestDatasetOutputContainsHTTP10AndHTTP2`
Expected: FAIL because sample dataset generation does not exist yet

- [ ] **Step 3: Implement CLI wiring and checked-in sample dataset**

```go
func main() {
    cfg, err := config.ParseCLI(os.Args[1:])
    if err != nil {
        log.Fatal(err)
    }
    assets, err := scanner.Run(context.Background(), cfg)
    if err != nil {
        log.Fatal(err)
    }
    if err := output.WriteJSONL(resolveWriter(cfg.OutputPath), assets); err != nil {
        log.Fatal(err)
    }
}
```

- [ ] **Step 4: Run the dataset test to verify it passes**

Run: `go test ./internal/scanner -run TestDatasetOutputContainsHTTP10AndHTTP2`
Expected: PASS

### Task 7: Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add concise usage documentation**

```md
## Usage

go run . scan --cidr 192.168.1.0/24 --ports 80,443,11434
```

- [ ] **Step 2: Run the full test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 3: Run a representative fixture-backed scan**

Run: `go test ./internal/scanner -run TestDatasetOutputContainsHTTP10AndHTTP2 -v`
Expected: PASS and logs prove output contains both protocol variants
