package config

import (
	"reflect"
	"testing"
)

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

func TestExpandCIDRsRejectsRangesThatAreTooLarge(t *testing.T) {
	_, err := ExpandCIDRs([]string{"10.0.0.0/8"})
	if err == nil {
		t.Fatal("expected oversized CIDR to return error")
	}
}
