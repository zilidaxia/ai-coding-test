package model

type Asset struct {
	IP          string              `json:"ip"`
	Port        int                 `json:"port"`
	Scheme      string              `json:"scheme,omitempty"`
	URL         string              `json:"url,omitempty"`
	Host        string              `json:"host"`
	Domain      []string            `json:"domain"`
	StatusCode  int                 `json:"status_code,omitempty"`
	Protocol    string              `json:"protocol,omitempty"`
	Header      map[string][]string `json:"header"`
	Body        string              `json:"body"`
	Title       string              `json:"title,omitempty"`
	Fingerprint []string            `json:"fingerprint,omitempty"`
	Confidence  string              `json:"confidence,omitempty"`
	TLS         bool                `json:"tls"`
}
