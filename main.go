package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mkideal/cli"
)

type HostInfo struct {
	IP    net.IP
	CName string
}

type Host interface {
	IsIP() bool
	IsCName() bool
}

func (h HostInfo) IsIP() bool {
	return h.IP != nil
}

func (h HostInfo) IsCName() bool {
	return h.CName != ""
}

type cacheEntry struct {
	rrs  []dns.RR
	time time.Time
}

type dnsProxy struct {
	upstream        Upstream
	records         map[string][]HostInfo
	ptrRecords      map[string]string
	cnameCache      map[uint16]map[string]cacheEntry
	localTTL        int
	verbose         bool
	upstreamTimeout time.Duration
}

func parseHostsScanner(scanner *bufio.Scanner) (map[string][]HostInfo, error) {
	records := make(map[string][]HostInfo)

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

		destField := fields[0]
		hostInfo := HostInfo{}

		if strings.HasPrefix(destField, "@") {
			hostInfo.CName = destField[1:] + "."
		} else {
			ip := net.ParseIP(destField)
			if ip == nil {
				continue
			}
			hostInfo.IP = ip
		}

		for _, host := range fields[1:] {
			dnsName := fmt.Sprintf("%s.", host)
			if _, ok := records[dnsName]; !ok {
				records[dnsName] = make([]HostInfo, 0)
			}
			records[dnsName] = append(records[dnsName], hostInfo)
		}
	}

	return records, nil
}

func parseHostsFile(path string) (map[string][]HostInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	return parseHostsScanner(scanner)
}

func (p *dnsProxy) queryCName(cname string, recordType uint16, onBehalfOf net.Addr) ([]dns.RR, error) {
	cache, ok := p.cnameCache[recordType]
	if !ok {
		return nil, fmt.Errorf("unsupported record type %d", recordType)
	}
	cached, ok := cache[cname]
	if ok && time.Since(cached.time) < time.Duration(p.localTTL)*time.Second {
		return cached.rrs, nil
	}

	// Request the domain's A and AAAA records from the upstream server.
	req := new(dns.Msg)
	req.SetQuestion(cname, recordType)
	req.RecursionDesired = true

	resp, err := p.respondToRequest(req, onBehalfOf)
	if err != nil {
		return nil, err
	}

	rrs := resp.Answer

	p.cnameCache[recordType][cname] = cacheEntry{rrs, time.Now()}
	return rrs, nil
}

func (p *dnsProxy) addLocalResponses(m *dns.Msg, onBehalfOf net.Addr) bool {
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

			records := p.records[q.Name]
			for _, record := range records {
				var ipStr string

				if record.IsIP() {
					ip := record.IP
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

				} else {
					if p.verbose {
						log.Printf(" -> querying CNAME %s\n", record.CName)
					}
					rrs, err := p.queryCName(record.CName, q.Qtype, onBehalfOf)
					if err != nil {
						log.Printf("Failed to query %s: %s\n", record.CName, err.Error())
						continue
					}
					m.Answer = append(m.Answer, rrs...)

					// Fixup the cname of the records.
					for _, rr := range m.Answer {
						rr.Header().Name = q.Name
					}

					foundEntries = true
					continue
				}
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

func NewUpstream(upstreamUrl string, timeout time.Duration) (Upstream, error) {
	u, err := url.Parse(upstreamUrl)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "https", "http":
		return &HttpUpstream{
			url: *u,
			client: &http.Client{
				Timeout: timeout,
			},
		}, nil
	case "dns":
		return &UdpUpstream{
			addr: u.Host,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream scheme: %s", u.Scheme)
	}
}

func getForwardedFor(addr net.Addr) net.IP {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP
	case *net.TCPAddr:
		return addr.IP
	default:
		log.Fatalf("Unsupported remote address type: %T", addr)
	}
	return nil
}

func (p *dnsProxy) respondToRequest(r *dns.Msg, onBehalfOf net.Addr) (resp *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		if !p.addLocalResponses(m, onBehalfOf) {
			if r.RecursionDesired {
				forwardedFor := getForwardedFor(onBehalfOf)
				return p.upstream.Exchange(r, forwardedFor)
			} else {
				m.SetRcode(r, dns.RcodeNameError)
			}
		} else {
			m.SetRcode(r, dns.RcodeSuccess)
		}
	}

	return m, nil
}

func (p *dnsProxy) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	resp, err := p.respondToRequest(r, w.RemoteAddr())

	if err != nil {
		log.Printf("Failed to query %s: %s\n", r.Question[0].Name, err.Error())
		resp = new(dns.Msg)
		resp.SetReply(r)
		resp.Compress = false
		resp.RecursionAvailable = true
		resp.SetRcode(r, dns.RcodeServerFailure)
	}

	err = w.WriteMsg(resp)
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
	Help            bool     `cli:"!h,help" usage:"Show this screen."`
	UpstreamUrl     string   `cli:"u,upstream" usage:"Upstream URL to forward queries to (for instance https://cloudflare-dns.com/dns-query)"`
	BindTo          string   `cli:"b,bind" usage:"Address to bind to (default: 0.0.0.0:53)" dft:"0.0.0.0:53"`
	HostsTTL        int      `cli:"t,ttl" usage:"TTL for hosts file entries (default: 10)" dft:"10"`
	HostsFiles      []string `cli:"H,hosts" usage:"Path to hosts file"`
	UpstreamTimeout int      `cli:"T,timeout" usage:"Timeout for upstream requests (default: 5)" dft:"5"`
	Verbose         bool     `cli:"V,verbose" usage:"Verbose output"`
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

	upstream, err := NewUpstream(cfg.UpstreamUrl, time.Duration(cfg.UpstreamTimeout)*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	proxy := &dnsProxy{
		upstream:        upstream,
		records:         make(map[string][]HostInfo),
		ptrRecords:      make(map[string]string),
		cnameCache:      make(map[uint16]map[string]cacheEntry),
		localTTL:        cfg.HostsTTL,
		verbose:         cfg.Verbose,
		upstreamTimeout: time.Duration(cfg.UpstreamTimeout) * time.Second,
	}

	proxy.cnameCache[dns.TypeA] = make(map[string]cacheEntry)
	proxy.cnameCache[dns.TypeAAAA] = make(map[string]cacheEntry)

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
			if ip.IsCName() {
				continue
			}

			reversed := reverseaddr(ip.IP)
			if _, ok := proxy.ptrRecords[reversed]; !ok {
				proxy.ptrRecords[reversed] = name
			}
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
