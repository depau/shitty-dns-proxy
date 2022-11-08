# Shitty DNS proxy

The DNS proxy I didn't want to write, but that I had to write since everything else just sucks.

Adapted from the following projects:

- [Simple Golang DNS server](https://gist.github.com/walm/0d67b4fb2d5daf3edd4fad3e13b162cb)
- [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy/blob/fd1868577652c639cce3da00e12ca548f421baf1/upstream/upstream_doh.go)

Use `DOCKER_BUILDKIT=1 docker build .` to build the image, or `docker-compose` without special requirements.

## What it does

It listens for plain old DNS requests and it forwards them to a DNS-over-HTTP(S) server of your choice.

It sets the `X-Forwarded-For` header to the IP address of the client that sent the request. This is useful to forward
the request to Adguard Home and be able to see which client made the request.

It also replies to requests to hosts found in specified `/etc/hosts`-like files.

## License

"Just do whatever you want with it, I didn't want to write this in the first place", MIT license.
