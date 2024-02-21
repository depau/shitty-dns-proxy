package main

import (
	"bufio"
	"github.com/miekg/dns"
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

123.45.67.89         host4
@one.one.one.one somehost
`
	scanner := bufio.NewScanner(strings.NewReader(hostsFile))
	records, err := parseHostsScanner(scanner)
	if err != nil {
		t.Error(err)
	}
	if len(records) != 6 {
		t.Error("Expected 6 records, got", len(records))
	}
	if len(records["host1."]) != 1 {
		t.Error("Expected 1 record for host1, got", len(records["host1."]))
	}
	if records["host1."][0].IP.String() != "123.123.123.123" {
		t.Error("Incorrect IP for host1: ", records["host1."][0])
	}
	if records["host2."][0].IP.String() != "123.123.123.123" {
		t.Error("Incorrect IP for host2: ", records["host2."][0])
	}
	if records["host3."][0].IP.String() != "1.1.1.1" {
		t.Error("Incorrect IP for host3: ", records["host3."][0])
	}
	if records["one.one.one.one."][0].IP.String() != "2606:4700:4700::1001" {
		t.Error("Incorrect IP for one.one.one.one: ", records["one.one.one.one."][0])
	}
	if records["host4."][0].IP.String() != "123.45.67.89" {
		t.Error("Incorrect IP for host4: ", records["host4."][0])
	}
	if records["somehost."][0].CName != "one.one.one.one." {
		t.Error("Incorrect CName for somehost: ", records["somehost."][0])
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

func TestLocalQuery(t *testing.T) {
	hostsFile := `
123.45.67.89 	   	 host1
2606:4700:4700::1001 one.one.one.one
@host1			     hostv4
@one.one.one.one     hostv6
`
	scanner := bufio.NewScanner(strings.NewReader(hostsFile))
	records, err := parseHostsScanner(scanner)
	if err != nil {
		t.Error(err)
	}

	proxy := dnsProxy{
		records:         records,
		cnameCache:      make(map[uint16]map[string]cacheEntry),
		ptrRecords:      make(map[string]string),
		localTTL:        1,
		verbose:         true,
		upstreamTimeout: 1,
	}
	proxy.cnameCache[dns.TypeA] = make(map[string]cacheEntry)
	proxy.cnameCache[dns.TypeAAAA] = make(map[string]cacheEntry)

	// Test A record
	msg := new(dns.Msg)
	msg.SetQuestion("host1.", dns.TypeA)
	resp, err := proxy.respondToRequest(msg, &net.TCPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 1234,
	})
	if err != nil {
		t.Error(err)
	}
	if len(resp.Answer) != 1 {
		t.Error("Expected 1 answer, got", len(resp.Answer))
	}
	if resp.Answer[0].Header().Name != "host1." {
		t.Error("Incorrect answer name: ", resp.Answer[0].Header().Name)
	}
	if resp.Answer[0].Header().Rrtype != dns.TypeA {
		t.Error("Incorrect answer type: ", resp.Answer[0].Header().Rrtype)
	}
	if resp.Answer[0].(*dns.A).A.String() != "123.45.67.89" {
		t.Error("Incorrect answer IP: ", resp.Answer[0].(*dns.A).A.String())
	}

	// Test AAAA record
	msg = new(dns.Msg)
	msg.SetQuestion("one.one.one.one.", dns.TypeAAAA)
	resp, err = proxy.respondToRequest(msg, &net.TCPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 1234,
	})
	if err != nil {
		t.Error(err)
	}
	if len(resp.Answer) != 1 {
		t.Error("Expected 1 answer, got", len(resp.Answer))
	}
	if resp.Answer[0].Header().Name != "one.one.one.one." {
		t.Error("Incorrect answer name: ", resp.Answer[0].Header().Name)
	}
	if resp.Answer[0].Header().Rrtype != dns.TypeAAAA {
		t.Error("Incorrect answer type: ", resp.Answer[0].Header().Rrtype)
	}
	if resp.Answer[0].(*dns.AAAA).AAAA.String() != "2606:4700:4700::1001" {
		t.Error("Incorrect answer IP: ", resp.Answer[0].(*dns.AAAA).AAAA.String())
	}

	// Test CNAME records
	msg = new(dns.Msg)
	msg.SetQuestion("hostv4.", dns.TypeA)
	resp, err = proxy.respondToRequest(msg, &net.TCPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 1234,
	})
	if err != nil {
		t.Error(err)
	}
	if len(resp.Answer) != 1 {
		t.Error("Expected 1 answer, got", len(resp.Answer))
	}
	if resp.Answer[0].Header().Name != "hostv4." {
		t.Error("Incorrect answer name: ", resp.Answer[0].Header().Name)
	}
	if resp.Answer[0].Header().Rrtype != dns.TypeA {
		t.Error("Incorrect answer type: ", resp.Answer[0].Header().Rrtype)
	}
	if resp.Answer[0].(*dns.A).A.String() != "123.45.67.89" {
		t.Error("Incorrect answer IP: ", resp.Answer[0].(*dns.A).A.String())
	}

	msg = new(dns.Msg)
	msg.SetQuestion("hostv6.", dns.TypeAAAA)
	resp, err = proxy.respondToRequest(msg, &net.TCPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 1234,
	})
	if err != nil {
		t.Error(err)
	}
	if len(resp.Answer) != 1 {
		t.Error("Expected 1 answer, got", len(resp.Answer))
	}
	if resp.Answer[0].Header().Name != "hostv6." {
		t.Error("Incorrect answer name: ", resp.Answer[0].Header().Name)
	}
	if resp.Answer[0].Header().Rrtype != dns.TypeAAAA {
		t.Error("Incorrect answer type: ", resp.Answer[0].Header().Rrtype)
	}
	if resp.Answer[0].(*dns.AAAA).AAAA.String() != "2606:4700:4700::1001" {
		t.Error("Incorrect answer IP: ", resp.Answer[0].(*dns.AAAA).AAAA.String())
	}
}
