package fingerprint

import "testing"

func TestEvaluateHighConfidenceFromAPIs(t *testing.T) {
	result := Evaluate(Evidence{
		HomepageBody:   `{"models":[{"name":"llama3"}]}`,
		APITagsBody:    `{"models":[{"name":"llama3"}]}`,
		APIVersionBody: `{"version":"0.5.7"}`,
	})
	if result.Confidence != "high" {
		t.Fatalf("Confidence = %q, want high", result.Confidence)
	}
	if !result.Matched {
		t.Fatal("expected matched result")
	}
}

func TestEvaluateRejectsGenericPage(t *testing.T) {
	result := Evaluate(Evidence{
		HomepageBody: "<html><title>Welcome</title></html>",
	})
	if result.Matched {
		t.Fatalf("expected generic page not to match")
	}
}
