package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	fhttp "github.com/Danny-Dasilva/fhttp"
	xproxy "golang.org/x/net/proxy"
	"h12.io/socks"
)

var version string = "DEV"

type proxy struct {
	mainURL            string
	forwardProxy       bool
	userAgent          string
	ja3                string
	timeout            int
	printErrors        bool
	upstreamProxy      string
	keepRequestHeaders headerNames
	newHTTPClient      func() (*fhttp.Client, error)
	mitmCA             *x509.Certificate
	mitmSigner         crypto.Signer
	mitmCertCache      map[string]*tls.Certificate
	mitmCertCacheMu    sync.Mutex
}

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

type singleConnListener struct {
	conn      net.Conn
	acceptOne sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: conn,
	}
}

func (listener *singleConnListener) Accept() (net.Conn, error) {
	var accepted bool
	listener.acceptOne.Do(func() {
		accepted = true
	})
	if accepted {
		return listener.conn, nil
	}
	return nil, net.ErrClosed
}

func (listener *singleConnListener) Close() error {
	return nil
}

func (listener *singleConnListener) Addr() net.Addr {
	return listener.conn.LocalAddr()
}

func loadMITMCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("MITM certificate must be a CA certificate")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key does not implement crypto.Signer")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func (handler *proxy) mitmCertificate(host string) (*tls.Certificate, error) {
	if handler.mitmCA == nil || handler.mitmSigner == nil {
		return nil, fmt.Errorf("CONNECT tunneling requires -mitm-ca-cert and -mitm-ca-key")
	}

	host = strings.TrimSuffix(host, ".")
	handler.mitmCertCacheMu.Lock()
	if handler.mitmCertCache == nil {
		handler.mitmCertCache = make(map[string]*tls.Certificate)
	}
	if cert := handler.mitmCertCache[host]; cert != nil {
		handler.mitmCertCacheMu.Unlock()
		return cert, nil
	}
	handler.mitmCertCacheMu.Unlock()

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	if handler.mitmCA.NotAfter.Before(template.NotAfter) {
		template.NotAfter = handler.mitmCA.NotAfter
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, handler.mitmCA, &key.PublicKey, handler.mitmSigner)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, handler.mitmCA.Raw},
		PrivateKey:  key,
		Leaf:        template,
	}

	handler.mitmCertCacheMu.Lock()
	handler.mitmCertCache[host] = cert
	handler.mitmCertCacheMu.Unlock()

	return cert, nil
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

func (handler *proxy) newHTTPConnectDialer(proxyURL *url.URL) xproxy.ContextDialer {
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
		connectRequest.Header.Set("User-Agent", handler.userAgent)
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

func (handler *proxy) upstreamDialer() (xproxy.ContextDialer, error) {
	if handler.upstreamProxy == "" {
		return xproxy.Direct, nil
	}

	proxyURL, err := url.Parse(handler.upstreamProxy)
	if err != nil {
		return nil, err
	}

	switch proxyURL.Scheme {
	case "http", "https":
		if proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q", handler.upstreamProxy)
		}
		return handler.newHTTPConnectDialer(proxyURL), nil
	case "socks4":
		dialer := socks.DialSocksProxy(socks.SOCKS4, proxyAddress(proxyURL))
		return contextDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			return dialer(network, address)
		}), nil
	case "socks5", "socks5h":
		dialer, err := xproxy.FromURL(proxyURL, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		contextDialer, ok := dialer.(xproxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("proxy %s does not support context dialing", handler.upstreamProxy)
		}
		return contextDialer, nil
	case "":
		return nil, fmt.Errorf("specify proxy scheme explicitly")
	default:
		return nil, fmt.Errorf("scheme %s is not supported", proxyURL.Scheme)
	}
}

func (handler *proxy) newCycleTLSHTTPClient() (*fhttp.Client, error) {
	dialer, err := handler.upstreamDialer()
	if err != nil {
		return nil, err
	}
	return &fhttp.Client{
		Transport: cycletls.NewTransportWithProxy(handler.ja3, handler.userAgent, dialer),
		Timeout:   time.Duration(handler.timeout) * time.Second,
	}, nil
}

func copyRequestHeadersToFHTTP(dst fhttp.Header, src http.Header, keepHeaders map[string]struct{}) {
	for name, value := range copyRequestHeaders(src, keepHeaders) {
		dst.Set(name, value)
	}
}

func connectHost(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

func certificateHost(targetHost string) string {
	host, _, err := net.SplitHostPort(targetHost)
	if err == nil {
		return host
	}
	return targetHost
}

func (handler *proxy) serveConnect(w http.ResponseWriter, req *http.Request) {
	if handler.mitmCA == nil || handler.mitmSigner == nil {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("CONNECT tunneling requires -mitm-ca-cert and -mitm-ca-key"))
		return
	}

	targetHost := connectHost(req)
	if targetHost == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("CONNECT request must include a target host"))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("response writer does not support hijacking"))
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Printf("ERROR ProxyClientHijack: %v", err)
		return
	}
	if buffered.Reader.Buffered() > 0 {
		_ = conn.Close()
		log.Printf("ERROR ProxyClientHijack: unexpected buffered CONNECT data")
		return
	}

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = conn.Close()
		log.Printf("ERROR ProxyClientConnect: %v", err)
		return
	}

	fallbackHost := certificateHost(targetHost)
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := fallbackHost
			if hello.ServerName != "" {
				host = hello.ServerName
			}
			return handler.mitmCertificate(host)
		},
	})

	innerHandler := &proxy{
		mainURL:            "https://" + targetHost,
		userAgent:          handler.userAgent,
		ja3:                handler.ja3,
		timeout:            handler.timeout,
		printErrors:        handler.printErrors,
		upstreamProxy:      handler.upstreamProxy,
		keepRequestHeaders: handler.keepRequestHeaders,
		newHTTPClient:      handler.newHTTPClient,
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(innerW http.ResponseWriter, innerReq *http.Request) {
			innerHandler.ServeHTTP(innerW, innerReq)
		}),
	}
	listener := newSingleConnListener(tlsConn)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed && err != net.ErrClosed {
		log.Printf("ERROR ProxyClientTLS: %v", err)
	}
}

func (handler *proxy) upstreamRequestURL(req *http.Request) (string, int, error) {
	if !handler.forwardProxy {
		return fmt.Sprintf("%s%s", handler.mainURL, req.URL), http.StatusOK, nil
	}

	if req.Method == http.MethodConnect {
		return "", http.StatusNotImplemented, fmt.Errorf("nested CONNECT requests are not supported")
	}
	if !req.URL.IsAbs() || req.URL.Host == "" {
		return "", http.StatusBadRequest, fmt.Errorf("forward proxy requests must use an absolute URL")
	}

	return req.URL.String(), http.StatusOK, nil
}

func (handler *proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if handler.forwardProxy && req.Method == http.MethodConnect {
		handler.serveConnect(w, req)
		return
	}

	newHTTPClient := handler.newHTTPClient
	if newHTTPClient == nil {
		newHTTPClient = handler.newCycleTLSHTTPClient
	}

	client, err := newHTTPClient()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	targetURL, status, err := handler.upstreamRequestURL(req)
	if err != nil {
		writeError(w, status, err)
		return
	}

	upstreamRequest, err := fhttp.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	copyRequestHeadersToFHTTP(upstreamRequest.Header, req.Header, handler.keepRequestHeaders.allowList())

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

	if handler.printErrors {
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
	handler := &proxy{}
	var listenAddress string
	var mitmCACertPath string
	var mitmCAKeyPath string

	flag.StringVar(&handler.userAgent, "ua", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0", "User-Agent to spoof, should align with JA3 token")
	flag.StringVar(&handler.ja3, "ja3", "771,4865-4867-4866-49195-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", "JA3 token to spoof, should align with user-agent")
	flag.StringVar(&listenAddress, "bind", "127.0.0.1:8888", "Listening address to bind to")
	flag.StringVar(&handler.upstreamProxy, "upstream-proxy", "", "Upstream proxy (if any required)")
	flag.StringVar(&mitmCACertPath, "mitm-ca-cert", "", "CA certificate PEM used to intercept HTTPS CONNECT requests in forward proxy mode")
	flag.StringVar(&mitmCAKeyPath, "mitm-ca-key", "", "CA private key PEM used to intercept HTTPS CONNECT requests in forward proxy mode")
	flag.IntVar(&handler.timeout, "timeout", 60, "Request timeout")
	flag.BoolVar(&handler.printErrors, "print-errors", false, "Print request and response when an error (4xx and 5xx) is returned from upstream server")
	flag.BoolVar(&handler.forwardProxy, "forward-proxy", false, "Run as a forward proxy and use each request's absolute URL as the upstream target")
	flag.Var(&handler.keepRequestHeaders, "keep-request-header", "Request header to forward even if normally stripped; can be used multiple times")
	versionPtr := flag.Bool("version", false, "display version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: %s [flags] [url]

Arguments:
  url string
	is the reverse proxy target URL where requests should be proxied to, after user-agent header and TLS flags are modified to achieve the required JA3 fingerprint. Omit when using -forward-proxy.

Flags:
`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionPtr {
		fmt.Println(version)
		return
	}

	if handler.forwardProxy && flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	if !handler.forwardProxy && flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if (mitmCACertPath == "") != (mitmCAKeyPath == "") {
		flag.Usage()
		os.Exit(2)
	}

	if !handler.forwardProxy {
		handler.mainURL = strings.TrimRight(flag.Arg(0), "/")
	}
	if mitmCACertPath != "" {
		var err error
		handler.mitmCA, handler.mitmSigner, err = loadMITMCA(mitmCACertPath, mitmCAKeyPath)
		if err != nil {
			log.Fatal(err)
		}
	}

	if handler.forwardProxy {
		log.Println("Up and running! Forward proxy listening at http://" + listenAddress)
	} else {
		log.Println("Up and running! All requests from http://" + listenAddress + " forwarded to " + handler.mainURL)
	}
	err := http.ListenAndServe(listenAddress, handler)
	if err != nil {
		log.Fatal(err)
	}
}
