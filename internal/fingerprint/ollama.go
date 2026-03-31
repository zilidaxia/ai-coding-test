package fingerprint

import (
	"encoding/json"
	"strings"
)

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

func Evaluate(e Evidence) Result {
	var result Result

	// 高置信度优先依赖 Ollama API 返回结构，而不是端口或单个关键字。
	if looksLikeOllamaTags(e.APITagsBody) {
		result.Fingerprints = append(result.Fingerprints, "api_tags_json")
	}
	if looksLikeOllamaVersion(e.APIVersionBody) {
		result.Fingerprints = append(result.Fingerprints, "api_version_ok")
	}
	if strings.Contains(strings.ToLower(e.HomepageBody), "ollama") {
		result.Fingerprints = append(result.Fingerprints, "homepage_keyword:ollama")
	}

	switch {
	case has(result.Fingerprints, "api_tags_json") && has(result.Fingerprints, "api_version_ok"):
		result.Matched = true
		result.Confidence = "high"
	case has(result.Fingerprints, "api_tags_json") || has(result.Fingerprints, "homepage_keyword:ollama"):
		result.Matched = true
		result.Confidence = "medium"
	default:
		result.Confidence = "none"
	}

	return result
}

func looksLikeOllamaTags(body string) bool {
	if strings.TrimSpace(body) == "" || !json.Valid([]byte(body)) {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, `"models"`) && strings.Contains(lower, `"name"`)
}

func looksLikeOllamaVersion(body string) bool {
	if strings.TrimSpace(body) == "" || !json.Valid([]byte(body)) {
		return false
	}
	return strings.Contains(strings.ToLower(body), `"version"`)
}

func has(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
