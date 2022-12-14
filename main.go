package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"github.com/mkideal/cli"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type dnsProxy struct {
	httpUrl    url.URL
	records    map[string][]net.IP
	ptrRecords map[string]string
	localTTL   int
	verbose    bool
}

func parseHostsScanner(scanner *bufio.Scanner) (map[string][]net.IP, error) {
	records := make(map[string][]net.IP)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		commentIndex := strings.Index(line, "#")
		if commentIndex != -1 {
			line = line[:commentIndex]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}

		for _, host := range fields[1:] {
			dnsName := fmt.Sprintf("%s.", host)
			if _, ok := records[dnsName]; !ok {
				records[dnsName] = make([]net.IP, 0)
			}
			records[dnsName] = append(records[dnsName], ip)
		}
	}

	return records, nil
}

func parseHostsFile(path string) (map[string][]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	return parseHostsScanner(scanner)
}

func (p *dnsProxy) addLocalResponses(m *dns.Msg) bool {
	foundEntries := false
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			fallthrough
		case dns.TypeAAAA:
			queryType := dns.TypeToString[q.Qtype]

			if p.verbose {
				log.Printf("%s query for %s\n", queryType, q.Name)
			}

			ips := p.records[q.Name]
			for _, ip := range ips {
				var ipStr string
				if q.Qtype == dns.TypeAAAA {
					if ip.To4() != nil {
						// Skip IPv4 addresses for AAAA queries, but prevent from asking upstream.
						foundEntries = true
						continue
					} else {
						ipStr = ip.String()
					}
				} else {
					if ip.To4() == nil {
						foundEntries = true
						continue
					}
					ipStr = ip.To4().String()
				}

				rr, err := dns.NewRR(fmt.Sprintf("%s %d %s %s", q.Name, p.localTTL, queryType, ipStr))
				if err != nil {
					log.Printf("Failed to create RR: %s\n", err.Error())
					continue
				}
				m.Answer = append(m.Answer, rr)
				foundEntries = true
			}
			break
		case dns.TypePTR:
			if p.verbose {
				log.Printf("PTR query for %s\n", q.Name)
			}
			ptr, ok := p.ptrRecords[q.Name]
			if !ok {
				continue
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s %d PTR %s", q.Name, p.localTTL, ptr))
			if err != nil {
				log.Printf("Failed to create RR: %s\n", err.Error())
				continue
			}
			m.Answer = append(m.Answer, rr)
			foundEntries = true
		default:
			if p.verbose {
				log.Printf("Unsupported query type %s for %s\n", dns.TypeToString[q.Qtype], q.Name)
			}
		}
	}
	if p.verbose {
		if foundEntries {
			log.Printf(" -> locally handled (%d records)\n", len(m.Answer))
		} else {
			log.Printf(" -> forwarding to upstream\n")
		}
	}
	return foundEntries
}

func exchangeHTTPSClient(
	url url.URL,
	client *http.Client,
	forwardedFor net.IP,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet

	u := url
	u.RawQuery = fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(buf))

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", url.String(), err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")
	httpReq.Header.Set("X-Forwarded-Proto", "https") // not really but lol
	httpReq.Header.Set("X-Forwarded-For", forwardedFor.String())
	httpReq.Header.Set("X-Real-IP", forwardedFor.String())

	httpResp, err := client.Do(httpReq)
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

	resp = &dns.Msg{}
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

func (p *dnsProxy) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		if !p.addLocalResponses(m) {
			if r.RecursionDesired {
				httpClient := &http.Client{}

				var forwardedForAddr net.Addr = w.RemoteAddr()
				var forwardedFor net.IP
				switch addr := forwardedForAddr.(type) {
				case *net.UDPAddr:
					forwardedFor = addr.IP
				case *net.TCPAddr:
					forwardedFor = addr.IP
				default:
					log.Fatalf("Unsupported remote address type: %T", addr)
				}

				resp, err := exchangeHTTPSClient(p.httpUrl, httpClient, forwardedFor, r)
				if err != nil {
					log.Printf("Failed to query %s: %s\n", r.Question[0].Name, err.Error())
					m.SetRcode(r, dns.RcodeServerFailure)
					goto localReply
				}

				err = w.WriteMsg(resp)
				if err != nil {
					m.SetRcode(r, dns.RcodeServerFailure)
					log.Printf("Failed to write response: %s\n", err.Error())
				}
				return
			} else {
				m.SetRcode(r, dns.RcodeNameError)
			}
		} else {
			m.SetRcode(r, dns.RcodeSuccess)
		}
	}

localReply:
	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("Failed to write response: %s\n", err.Error())
	}
}

// from net.dnsclient
func reverseaddr(ip net.IP) (arpa string) {
	const hexDigit = "0123456789abcdef"

	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[15], ip[14], ip[13], ip[12])
	}
	// Must be IPv6
	buf := make([]byte, 0, len(ip)*4+len("ip6.arpa."))
	//Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF],
			'.',
			hexDigit[v>>4],
			'.')
	}
	//Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf)
}

type config struct {
	Help        bool     `cli:"!h,help" usage:"Show this screen."`
	UpstreamUrl string   `cli:"u,upstream" usage:"Upstream URL to forward queries to (for instance https://cloudflare-dns.com/dns-query)"`
	BindTo      string   `cli:"b,bind" usage:"Address to bind to (default: 0.0.0.0:53)" dft:"0.0.0.0:53"`
	HostsTTL    int      `cli:"t,ttl" usage:"TTL for hosts file entries (default: 10)" dft:"10"`
	HostsFiles  []string `cli:"H,hosts" usage:"Path to hosts file"`
	Verbose     bool     `cli:"V,verbose" usage:"Verbose output"`
}

func (argv *config) AutoHelp() bool {
	return argv.Help
}

func main() {
	cfg := config{}
	ret := cli.Run(&cfg, func(ctx *cli.Context) error {
		return nil
	}, "Davide's shitty DNS proxy")
	if ret != 0 || cfg.Help {
		return
	}

	u, err := url.Parse(cfg.UpstreamUrl)
	if err != nil {
		log.Fatal(err)
	}

	proxy := &dnsProxy{
		httpUrl:    *u,
		records:    make(map[string][]net.IP),
		ptrRecords: make(map[string]string),
		localTTL:   cfg.HostsTTL,
		verbose:    cfg.Verbose,
	}

	count := 0
	for _, hostsFile := range cfg.HostsFiles {
		records, err := parseHostsFile(hostsFile)
		if err != nil {
			log.Fatal(err)
		}
		for k, v := range records {
			proxy.records[k] = v
			count += len(v)
		}
	}

	for name, ips := range proxy.records {
		for _, ip := range ips {
			reversed := reverseaddr(ip)
			proxy.ptrRecords[reversed] = name
		}
	}

	if len(cfg.HostsFiles) > 0 {
		log.Printf("Loaded %d records from %d hosts files", count, len(cfg.HostsFiles))
	}

	dns.HandleFunc(".", proxy.handleDnsRequest)

	// start server
	server := &dns.Server{Addr: cfg.BindTo, Net: "udp"}
	log.Printf("Serving DNS on %s/udp\n", cfg.BindTo)

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to run server: %s\n ", err.Error())
	}
	err = server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to shutdown server: %s\n ", err.Error())
	}
}
