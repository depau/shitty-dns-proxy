package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/miekg/dns"
)

// Upstream is the interface for a DNS upstream.
type Upstream interface {
	// Exchange forwards a DNS query to the upstream server.
	Exchange(*dns.Msg, net.IP) (*dns.Msg, error)
}

// UdpUpstream is an upstream that uses UDP.
type UdpUpstream struct {
	addr string
}

// Exchange forwards a DNS query to the upstream server.
func (u *UdpUpstream) Exchange(req *dns.Msg, _ net.IP) (*dns.Msg, error) {
	dnsClient := new(dns.Client)
	resp, _, err := dnsClient.Exchange(req, u.addr)
	return resp, err
}

// HttpUpstream is an upstream that uses DNS-over-HTTPS.
type HttpUpstream struct {
	url    url.URL
	client *http.Client
}

// Exchange forwards a DNS query to the upstream server.
func (h *HttpUpstream) Exchange(req *dns.Msg, forwardedFor net.IP) (*dns.Msg, error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet

	u := h.url
	u.RawQuery = fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(buf))

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", h.url.String(), err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")
	httpReq.Header.Set("X-Forwarded-Proto", "https") // not really but lol
	httpReq.Header.Set("X-Forwarded-For", forwardedFor.String())
	httpReq.Header.Set("X-Real-IP", forwardedFor.String())

	httpResp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", u.String(), err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", u.String(), err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil,
			fmt.Errorf(
				"expected status %d, got %d from %s",
				http.StatusOK,
				httpResp.StatusCode,
				u.String(),
			)
	}

	resp := &dns.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			u.String(),
			body,
			err,
		)
	}

	if resp.Id != req.Id {
		err = dns.ErrId
	}

	return resp, err
}
