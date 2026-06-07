package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	fhttp "github.com/Danny-Dasilva/fhttp"
	"golang.org/x/net/proxy"
	"h12.io/socks"
)

var version string = "DEV"

var mainURL string
var userAgent string
var ja3 string
var listenAddress string
var timeout int
var printErrors bool
var upstreamProxy string
var keepRequestHeaders headerNames
var newHTTPClient = newCycleTLSHTTPClient

func writeError(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	_, errWrite := w.Write([]byte(err.Error()))
	if errWrite != nil {
		log.Printf("ERROR Proxy2Client: %v", errWrite)
	}
}

func printIfHTTPErrorCode(request *http.Request, response *fhttp.Response) {
	if response.StatusCode >= 400 {
		log.Printf("Response status %d", response.StatusCode)
		log.Printf("== request ==")
		log.Printf("%v", request)
		log.Printf("== response ==")
		log.Printf("%s %s", response.Proto, response.Status)
	}
}

func copyResponseHeaders(dst http.Header, src fhttp.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

var hopByHopRequestHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

type headerNames []string

func (headers *headerNames) String() string {
	return strings.Join(*headers, ",")
}

func (headers *headerNames) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("header name cannot be empty")
	}

	*headers = append(*headers, value)
	return nil
}

func (headers headerNames) allowList() map[string]struct{} {
	allowList := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		allowList[strings.ToLower(header)] = struct{}{}
	}
	return allowList
}

func requestConnectionHeaders(headers http.Header) map[string]struct{} {
	connectionHeaders := make(map[string]struct{})

	for _, headerValue := range headers.Values("Connection") {
		for _, headerName := range strings.Split(headerValue, ",") {
			headerName = strings.ToLower(strings.TrimSpace(headerName))
			if headerName != "" {
				connectionHeaders[headerName] = struct{}{}
			}
		}
	}

	return connectionHeaders
}

func copyRequestHeaders(src http.Header, keepHeaders map[string]struct{}) map[string]string {
	forwardedHeaders := make(map[string]string)
	connectionHeaders := requestConnectionHeaders(src)

	for name, values := range src {
		headerName := strings.ToLower(name)
		if strings.EqualFold(name, "User-Agent") {
			continue
		}
		if _, keep := keepHeaders[headerName]; !keep {
			if _, ok := hopByHopRequestHeaders[headerName]; ok {
				continue
			}
			if _, ok := connectionHeaders[headerName]; ok {
				continue
			}
		}
		if len(values) == 0 {
			continue
		}
		// cycleTLS does not support multiple values for an header
		if len(values) > 1 {
			log.Printf("WARNING: header %s had all values dropped but 1", name)
		}
		forwardedHeaders[name] = values[0]
	}

	return forwardedHeaders
}

type contextDialerFunc func(context.Context, string, string) (net.Conn, error)

func (fn contextDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return fn(ctx, network, address)
}

func defaultProxyPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks4", "socks5", "socks5h":
		return "1080"
	default:
		return ""
	}
}

func proxyAddress(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	return net.JoinHostPort(proxyURL.Hostname(), defaultProxyPort(proxyURL.Scheme))
}

func newHTTPConnectDialer(proxyURL *url.URL) proxy.ContextDialer {
	proxyAddr := proxyAddress(proxyURL)
	return contextDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, network, proxyAddr)
		if err != nil {
			return nil, err
		}

		if proxyURL.Scheme == "https" {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname()})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = tlsConn
		}

		connectRequest := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: address},
			Host:   address,
			Header: make(http.Header),
		}
		connectRequest.Header.Set("User-Agent", userAgent)
		if proxyURL.User != nil && proxyURL.User.Username() != "" {
			password, _ := proxyURL.User.Password()
			token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
			connectRequest.Header.Set("Proxy-Authorization", "Basic "+token)
		}

		if err := connectRequest.Write(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), connectRequest)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			_ = conn.Close()
			return nil, fmt.Errorf("proxy responded with non-200 status: %s", response.Status)
		}
		_ = response.Body.Close()
		return conn, nil
	})
}

func upstreamDialer() (proxy.ContextDialer, error) {
	if upstreamProxy == "" {
		return proxy.Direct, nil
	}

	proxyURL, err := url.Parse(upstreamProxy)
	if err != nil {
		return nil, err
	}

	switch proxyURL.Scheme {
	case "http", "https":
		if proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q", upstreamProxy)
		}
		return newHTTPConnectDialer(proxyURL), nil
	case "socks4":
		dialer := socks.DialSocksProxy(socks.SOCKS4, proxyAddress(proxyURL))
		return contextDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			return dialer(network, address)
		}), nil
	case "socks5", "socks5h":
		dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			return nil, err
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("proxy %s does not support context dialing", upstreamProxy)
		}
		return contextDialer, nil
	case "":
		return nil, fmt.Errorf("specify proxy scheme explicitly")
	default:
		return nil, fmt.Errorf("scheme %s is not supported", proxyURL.Scheme)
	}
}

func newCycleTLSHTTPClient() (*fhttp.Client, error) {
	dialer, err := upstreamDialer()
	if err != nil {
		return nil, err
	}
	return &fhttp.Client{
		Transport: cycletls.NewTransportWithProxy(ja3, userAgent, dialer),
		Timeout:   time.Duration(timeout) * time.Second,
	}, nil
}

func copyRequestHeadersToFHTTP(dst fhttp.Header, src http.Header, keepHeaders map[string]struct{}) {
	for name, value := range copyRequestHeaders(src, keepHeaders) {
		dst.Set(name, value)
	}
}

func hello(w http.ResponseWriter, req *http.Request) {
	client, err := newHTTPClient()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	upstreamRequest, err := fhttp.NewRequestWithContext(req.Context(), req.Method, fmt.Sprintf("%s%s", mainURL, req.URL), req.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	copyRequestHeadersToFHTTP(upstreamRequest.Header, req.Header, keepRequestHeaders.allowList())

	response, err := client.Do(upstreamRequest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Printf("ERROR UpstreamResponseClose: %v", err)
		}
	}()

	if printErrors {
		printIfHTTPErrorCode(req, response)
	}

	copyResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, err = io.Copy(w, response.Body)
	if err != nil {
		log.Printf("ERROR Proxy2Client: %v", err)
	}
}

func main() {
	flag.StringVar(&userAgent, "ua", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0", "User-Agent to spoof, should align with JA3 token")
	flag.StringVar(&ja3, "ja3", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", "JA3 token to spoof, should align with user-agent")
	flag.StringVar(&listenAddress, "bind", "127.0.0.1:8888", "Listening address to bind to")
	flag.StringVar(&upstreamProxy, "upstream-proxy", "", "Upstream proxy (if any required)")
	flag.IntVar(&timeout, "timeout", 60, "Request timeout")
	flag.BoolVar(&printErrors, "print-errors", false, "Print request and response when an error (4xx and 5xx) is returned from upstream server")
	flag.Var(&keepRequestHeaders, "keep-request-header", "Request header to forward even if normally stripped; can be used multiple times")
	versionPtr := flag.Bool("version", false, "display version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: %s [flags] [url]

Arguments:
  url string
	is the target URL where requests should be proxied to, after user-agent header and TLS flags are modified to achieve the required JA3 fingerprint.

Flags:
`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionPtr {
		fmt.Println(version)
		return
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	mainURL = strings.TrimRight(flag.Arg(0), "/")

	http.HandleFunc("/", hello)
	log.Println("Up and running! All requests from http://" + listenAddress + " forwarded to " + mainURL)
	err := http.ListenAndServe(listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}
