package main

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestParseHostsFile(t *testing.T) {
	hostsFile := `
# comment
123.123.123.123 host1 host2 # comment
            # comment
1.1.1.1	host3#comment
2606:4700:4700::1001 one.one.one.one
`
	scanner := bufio.NewScanner(strings.NewReader(hostsFile))
	records, err := parseHostsScanner(scanner)
	if err != nil {
		t.Error(err)
	}
	if len(records) != 4 {
		t.Error("Expected 4 records, got", len(records))
	}
	if len(records["host1."]) != 1 {
		t.Error("Expected 1 record for host1, got", len(records["host1."]))
	}
	if records["host1."][0].String() != "123.123.123.123" {
		t.Error("Incorrect IP for host1: ", records["host1."][0])
	}
	if records["host2."][0].String() != "123.123.123.123" {
		t.Error("Incorrect IP for host2: ", records["host2."][0])
	}
	if records["host3."][0].String() != "1.1.1.1" {
		t.Error("Incorrect IP for host3: ", records["host3."][0])
	}
	if records["one.one.one.one."][0].String() != "2606:4700:4700::1001" {
		t.Error("Incorrect IP for one.one.one.one: ", records["one.one.one.one."][0])
	}
}

func TestReverseAddress(t *testing.T) {
	if reverseaddr(net.ParseIP("123.123.123.123")) != "123.123.123.123.in-addr.arpa." {
		t.Error("Incorrect reverse address for 123.123.123.123")
	}
	if reverseaddr(net.ParseIP("2606:4700:4700::1001")) != "1.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa." {
		t.Error("Incorrect reverse address for 2606:4700:4700::1001")
	}
}
