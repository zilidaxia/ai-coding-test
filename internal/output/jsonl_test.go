package output

import (
	"bytes"
	"strings"
	"testing"

	"ai-coding-test/internal/model"
)

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
