# gotlsproxy

Reverse proxy with JA3 spoofing

## Usage

```
$ gotlsproxy -h
usage: /gotlsproxy [flags] [url]

Arguments:
  url string
	is the target URL where requests should be proxied to, after user-agent header and TLS flags are modified to achieve the required JA3 fingerprint.

Flags:
  -bind string
    	Listening address to bind to (default "127.0.0.1:8888")
  -ja3 string
    	JA3 token to spoof, should align with user-agent (default "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0")
  -print-errors
    	Print request and response when an error (4xx and 5xx) is returned from upstream server
  -timeout int
    	Request timeout (default 60)
  -ua string
    	User-Agent to spoof, should align with JA3 token (default "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0")
  -upstream-proxy string
    	Upstream proxy (if any required)
  -version
    	display version
```

Also available via docker image, hosted both in [Docker Hub](https://hub.docker.com/r/fopina/gotlsproxy) and [GHCR](https://github.com/fopina/gotlsproxy/pkgs/container/gotlsproxy)

```
$ docker run --rm fopina/gotlsproxy:0.3 -version
0.3
$ docker run --rm ghcr.io/fopina/gotlsproxy:0.3 -version
0.3
```

### Validation

We can use an online service to validate that JA3 fingerprint does change, such as https://ja3.zone/check

```
$ curl -s https://check.ja3.zone/ | jq
{
  "hash": "2bab0327a296230f9f6427341e716ea0",
  "fingerprint": "771,4866-4867-4865-49200-49196-49192-49188-49172-49162-159-107-57-52393-52392-52394-65413-196-136-129-157-61-53-192-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,43-51-0-11-10-13-16,29-23-24-25,0",
  ...
  "user_agent": "curl/7.79.1"
}
```

Now, reverse proxied by `gotlsproxy`

```
$ gotlsproxy https://check.ja3.zone/
```

```
$ curl -s localhost:8888 | jq
{
  "hash": "b20b44b18b853ef29ab773e921b03422",
  "fingerprint": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
  ...
  "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0"
}
```

The fingerprint seen by the server is exactly the one spoofed by gotlsproxy (default value of `-ja3` flag in this example)
