# Shitty DNS proxy

The DNS proxy I didn't want to write, but that I had to write since everything else just sucks.

Adapted from the following projects:

- [Simple Golang DNS server](https://gist.github.com/walm/0d67b4fb2d5daf3edd4fad3e13b162cb)
- [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy/blob/fd1868577652c639cce3da00e12ca548f421baf1/upstream/upstream_doh.go)

Use `DOCKER_BUILDKIT=1 docker build .` to build the image, or `docker-compose` without special requirements.

## What it does

It listens for plain old DNS requests (UDP) and forwards them to an upstream of your choice. The upstream can be either:

- a DNS-over-HTTP(S) server (`https://` or `http://` URL), or
- a plain DNS server over UDP (`dns://host:port`).

For DoH upstreams it sets the `X-Forwarded-For` and `X-Real-IP` headers to the IP address of the client that sent the
request. This is useful to forward the request to Adguard Home and be able to see which client made the request.

It also replies to requests to hosts found in specified `/etc/hosts`-like files, handling `A`, `AAAA` and (automatically
generated) `PTR` queries. CNAME-style entries are resolved through the upstream and cached for the configured TTL.

## Usage

```
-u, --upstream    Upstream URL to forward queries to (e.g. https://cloudflare-dns.com/dns-query or dns://1.1.1.1:53)
-b, --bind        Address to bind to (default: 0.0.0.0:53)
-t, --ttl         TTL for hosts file entries (default: 10)
-H, --hosts       Path to a hosts file (may be repeated)
-T, --timeout     Timeout for upstream requests in seconds (default: 5)
-V, --verbose     Verbose output
-h, --help        Show the help screen
```

### Hosts file format

The hosts file format is the same as the one used by `/etc/hosts`, with some extra features:

- Comments are allowed, and they start with a `#` character.
- All whitespace is ignored.
- You can define CNAME-like entries by using a domain name as the target of an entry, prefixed by a `@` character.

Example:

```
# This is a comment
123.45.67.89    example.com       # This is also a comment
@example.com    example.org       # This also resolves to 123.45.67.89
@google.com     google-alias.com  # This resolves to whatever google.com resolves to
```

## Running as a launchd daemon (macOS)

A template is provided in `eu.depau.shitty-dns-proxy.plist`. Edit the `ProgramArguments` (upstream, bind address,
hosts files) to taste, then install it as a system daemon (port 53 needs root):

```
go build -o shitty-dns-proxy
sudo cp shitty-dns-proxy /usr/local/bin/
sudo cp eu.depau.shitty-dns-proxy.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/eu.depau.shitty-dns-proxy.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/eu.depau.shitty-dns-proxy.plist
```

The `chown` matters: launchd refuses plists in `/Library/LaunchDaemons` that aren't owned by `root:wheel`
(the symptom is `Load failed: 5: Input/output error`).

Logs go to `/var/log/shitty-dns-proxy.log`. To stop: `sudo launchctl bootout system /Library/LaunchDaemons/eu.depau.shitty-dns-proxy.plist`.

## License

"Just do whatever you want with it, I didn't want to write this in the first place", MIT license.
