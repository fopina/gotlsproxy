package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/Danny-Dasilva/fhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const scrapflyJA3Endpoint = "https://tools.scrapfly.io"
const userAgentEchoEndpoint = "https://httpbingo.org"

type scrapflyJA3Response struct {
	JA3       string `json:"ja3"`
	JA3Digest string `json:"ja3_digest"`
}

type userAgentResponse struct {
	UserAgent string `json:"user-agent"`
}

type smokeFingerprint struct {
	name          string
	userAgent     string
	ja3           string
	ciphers       string
	extensions    string
	supported     string
	pointFormats  string
	reportedJA3   string
	reportedJA3MD string
}

type roundTripFunc func(*fhttp.Request) (*fhttp.Response, error)

func (fn roundTripFunc) RoundTrip(req *fhttp.Request) (*fhttp.Response, error) {
	return fn(req)
}

type lockedResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	mu     sync.Mutex
	code   int
}

func newLockedResponseRecorder() *lockedResponseRecorder {
	return &lockedResponseRecorder{header: make(http.Header), code: http.StatusOK}
}

func (recorder *lockedResponseRecorder) Header() http.Header {
	return recorder.header
}

func (recorder *lockedResponseRecorder) WriteHeader(statusCode int) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.code = statusCode
}

func (recorder *lockedResponseRecorder) Write(body []byte) (int, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.body.Write(body)
}

func (recorder *lockedResponseRecorder) BodyString() string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.body.String()
}

func (recorder *lockedResponseRecorder) Code() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.code
}

func newTestProxy(roundTrip func(*fhttp.Request) (*fhttp.Response, error)) *proxy {
	return &proxy{
		mainURL:       "https://upstream.example/base",
		userAgent:     "gotlsproxy-test",
		timeout:       10,
		upstreamProxy: "",
		newHTTPClient: func() (*fhttp.Client, error) {
			return &fhttp.Client{Transport: roundTripFunc(roundTrip)}, nil
		},
	}
}

func newFHTTPResponse(statusCode int, headers fhttp.Header, body io.Reader) *fhttp.Response {
	return &fhttp.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        headers,
		Body:          io.NopCloser(body),
		ContentLength: -1,
	}
}

func gzipBytes(t *testing.T, body string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func generateTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "gotlsproxy test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return cert, key, certPEM, keyPEM
}

func fetchScrapflyJA3(t *testing.T, client *http.Client, url string) scrapflyJA3Response {
	t.Helper()

	resp, err := client.Get(url)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var fingerprint scrapflyJA3Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&fingerprint))
	require.NotEmpty(t, fingerprint.JA3)
	require.NotEmpty(t, fingerprint.JA3Digest)
	return fingerprint
}

func fetchUserAgent(t *testing.T, client *http.Client, url string) string {
	t.Helper()

	resp, err := client.Get(url)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var echoed userAgentResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&echoed))
	require.NotEmpty(t, echoed.UserAgent)
	return echoed.UserAgent
}

func TestCopyResponseHeaders(t *testing.T) {
	headers := make(http.Header)

	copyResponseHeaders(headers, fhttp.Header{
		"Content-Type":  []string{"application/json"},
		"Set-Cookie":    []string{"session=abc; HttpOnly"},
		"Cache-Control": []string{"no-store"},
	})

	assert.Equal(t, "application/json", headers.Get("Content-Type"))
	assert.Equal(t, []string{"session=abc; HttpOnly"}, headers.Values("Set-Cookie"))
	assert.Equal(t, "no-store", headers.Get("Cache-Control"))
}

func TestCopyResponseHeadersPreservesEntityHeadersForStreamingResponse(t *testing.T) {
	headers := make(http.Header)

	copyResponseHeaders(headers, fhttp.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Length":   []string{"123"},
		"Content-Type":     []string{"text/plain"},
	})

	assert.Equal(t, "gzip", headers.Get("Content-Encoding"))
	assert.Equal(t, "123", headers.Get("Content-Length"))
	assert.Equal(t, "text/plain", headers.Get("Content-Type"))
}

func TestCopyRequestHeaders(t *testing.T) {
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer token"},
		"X-Trace-Id":    []string{"abc123"},
		"User-Agent":    []string{"curl/8.0"},
	}

	forwardedHeaders := copyRequestHeaders(headers, nil)

	assert.Equal(t, "application/json", forwardedHeaders["Accept"])
	assert.Equal(t, "Bearer token", forwardedHeaders["Authorization"])
	assert.Equal(t, "abc123", forwardedHeaders["X-Trace-Id"])
	assert.NotContains(t, forwardedHeaders, "User-Agent")
}

func TestCopyRequestHeadersDropsHopByHopHeaders(t *testing.T) {
	headers := http.Header{
		"Connection":          []string{"keep-alive"},
		"Keep-Alive":          []string{"timeout=5"},
		"Proxy-Authenticate":  []string{"Basic"},
		"Proxy-Authorization": []string{"Basic credentials"},
		"Proxy-Connection":    []string{"keep-alive"},
		"Te":                  []string{"trailers"},
		"Trailer":             []string{"Expires"},
		"Transfer-Encoding":   []string{"chunked"},
		"Upgrade":             []string{"websocket"},
		"X-Forward-Me":        []string{"yes"},
	}

	forwardedHeaders := copyRequestHeaders(headers, nil)

	assert.Equal(t, map[string]string{"X-Forward-Me": "yes"}, forwardedHeaders)
}

func TestCopyRequestHeadersDropsConnectionNamedHeaders(t *testing.T) {
	headers := http.Header{
		"Connection":    []string{"X-Debug, x-remove-me"},
		"X-Debug":       []string{"debug"},
		"X-Remove-Me":   []string{"remove"},
		"X-Forward-Me":  []string{"keep"},
		"Cache-Control": []string{"no-cache"},
	}

	forwardedHeaders := copyRequestHeaders(headers, nil)

	assert.Equal(t, "keep", forwardedHeaders["X-Forward-Me"])
	assert.Equal(t, "no-cache", forwardedHeaders["Cache-Control"])
	assert.NotContains(t, forwardedHeaders, "Connection")
	assert.NotContains(t, forwardedHeaders, "X-Debug")
	assert.NotContains(t, forwardedHeaders, "X-Remove-Me")
}

func TestCopyRequestHeadersKeepsAllowedHopByHopHeaders(t *testing.T) {
	headers := http.Header{
		"Connection":   []string{"X-Debug"},
		"Keep-Alive":   []string{"timeout=5"},
		"X-Debug":      []string{"debug"},
		"Upgrade":      []string{"websocket"},
		"X-Forward-Me": []string{"keep"},
	}

	keepHeaders := headerNames{"keep-alive", "X-Debug"}.allowList()
	forwardedHeaders := copyRequestHeaders(headers, keepHeaders)

	assert.Equal(t, "timeout=5", forwardedHeaders["Keep-Alive"])
	assert.Equal(t, "debug", forwardedHeaders["X-Debug"])
	assert.Equal(t, "keep", forwardedHeaders["X-Forward-Me"])
	assert.NotContains(t, forwardedHeaders, "Connection")
	assert.NotContains(t, forwardedHeaders, "Upgrade")
}

func TestServeHTTPForwardsPathQueryHeadersCookiesAndPostBody(t *testing.T) {
	var upstreamMethod string
	var upstreamURL string
	var upstreamHeaders fhttp.Header
	var upstreamBody string

	handler := newTestProxy(func(req *fhttp.Request) (*fhttp.Response, error) {
		var err error
		upstreamMethod = req.Method
		upstreamURL = req.URL.String()
		upstreamHeaders = req.Header.Clone()
		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		upstreamBody = string(bodyBytes)

		return newFHTTPResponse(http.StatusOK, fhttp.Header{}, strings.NewReader("ok")), nil
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/items?search=a%20b&limit=10", strings.NewReader("payload=abc"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Trace-Id", "trace-123")
	request.Header.Set("User-Agent", "client-agent")
	request.AddCookie(&http.Cookie{Name: "session", Value: "abc"})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, http.MethodPost, upstreamMethod)
	assert.Equal(t, "https://upstream.example/base/v1/items?search=a%20b&limit=10", upstreamURL)
	assert.Equal(t, "application/x-www-form-urlencoded", upstreamHeaders.Get("Content-Type"))
	assert.Equal(t, "trace-123", upstreamHeaders.Get("X-Trace-Id"))
	assert.Equal(t, "session=abc", upstreamHeaders.Get("Cookie"))
	assert.Empty(t, upstreamHeaders.Get("User-Agent"))
	assert.Equal(t, "payload=abc", upstreamBody)
}

func TestServeHTTPForwardProxyUsesAbsoluteRequestURL(t *testing.T) {
	var upstreamMethod string
	var upstreamURL string
	var upstreamHeaders fhttp.Header
	var upstreamBody string

	handler := newTestProxy(func(req *fhttp.Request) (*fhttp.Response, error) {
		var err error
		upstreamMethod = req.Method
		upstreamURL = req.URL.String()
		upstreamHeaders = req.Header.Clone()
		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		upstreamBody = string(bodyBytes)

		return newFHTTPResponse(http.StatusOK, fhttp.Header{}, strings.NewReader("ok")), nil
	})
	handler.forwardProxy = true
	handler.mainURL = ""

	request := httptest.NewRequest(http.MethodPost, "https://target.example/v1/items?search=a%20b&limit=10", strings.NewReader("payload=abc"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Proxy-Authorization", "Basic credentials")
	request.Header.Set("X-Trace-Id", "trace-123")
	request.Header.Set("User-Agent", "client-agent")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, http.MethodPost, upstreamMethod)
	assert.Equal(t, "https://target.example/v1/items?search=a%20b&limit=10", upstreamURL)
	assert.Equal(t, "application/x-www-form-urlencoded", upstreamHeaders.Get("Content-Type"))
	assert.Equal(t, "trace-123", upstreamHeaders.Get("X-Trace-Id"))
	assert.Empty(t, upstreamHeaders.Get("Proxy-Authorization"))
	assert.Empty(t, upstreamHeaders.Get("User-Agent"))
	assert.Equal(t, "payload=abc", upstreamBody)
}

func TestServeHTTPForwardProxyRejectsOriginFormRequest(t *testing.T) {
	handler := newTestProxy(func(_ *fhttp.Request) (*fhttp.Response, error) {
		t.Fatal("upstream request should not be sent")
		return nil, nil
	})
	handler.forwardProxy = true
	handler.mainURL = ""

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/relative/path", nil))

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "absolute URL")
}

func TestServeHTTPForwardProxyRejectsConnectRequests(t *testing.T) {
	handler := newTestProxy(func(_ *fhttp.Request) (*fhttp.Response, error) {
		t.Fatal("upstream request should not be sent")
		return nil, nil
	})
	handler.forwardProxy = true
	handler.mainURL = ""

	request := httptest.NewRequest(http.MethodConnect, "https://target.example:443", nil)
	request.URL.Scheme = ""
	request.URL.Host = "target.example:443"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusNotImplemented, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "requires -mitm-ca-cert")
}

func TestServeHTTPForwardProxyHandlesHTTPSConnectWithMITMCA(t *testing.T) {
	ca, key, _, _ := generateTestCA(t)
	var upstreamMethod string
	var upstreamURL string
	var upstreamHeaders fhttp.Header

	handler := newTestProxy(func(req *fhttp.Request) (*fhttp.Response, error) {
		upstreamMethod = req.Method
		upstreamURL = req.URL.String()
		upstreamHeaders = req.Header.Clone()

		return newFHTTPResponse(http.StatusOK, fhttp.Header{
			"Content-Type": []string{"text/plain"},
		}, strings.NewReader("ok")), nil
	})
	handler.forwardProxy = true
	handler.mainURL = ""
	handler.mitmCA = ca
	handler.mitmSigner = key

	server := httptest.NewServer(handler)
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
	}}

	response, err := client.Get("https://target.example/v1/items?search=a%20b")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, response.Body.Close())
	}()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "ok", string(body))
	assert.Equal(t, http.MethodGet, upstreamMethod)
	assert.Equal(t, "https://target.example:443/v1/items?search=a%20b", upstreamURL)
	assert.Empty(t, upstreamHeaders.Get("User-Agent"))
}

func TestServeHTTPForwardsStatusHeadersAndCookies(t *testing.T) {
	handler := newTestProxy(func(_ *fhttp.Request) (*fhttp.Response, error) {
		return newFHTTPResponse(http.StatusTeapot, fhttp.Header{
			"Cache-Control": []string{"no-store"},
			"Content-Type":  []string{"application/json"},
			"Set-Cookie":    []string{"session=abc; HttpOnly", "theme=dark"},
		}, strings.NewReader(`{"error":"teapot"}`)), nil
	})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	response := recorder.Result()
	defer func() {
		require.NoError(t, response.Body.Close())
	}()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusTeapot, response.StatusCode)
	assert.Equal(t, "application/json", response.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	assert.Equal(t, []string{"session=abc; HttpOnly", "theme=dark"}, response.Header.Values("Set-Cookie"))
	assert.Equal(t, `{"error":"teapot"}`, string(body))
}

func TestServeHTTPForwardsCompressedUpstreamResponse(t *testing.T) {
	compressedBody := gzipBytes(t, "compressed response")
	handler := newTestProxy(func(_ *fhttp.Request) (*fhttp.Response, error) {
		return newFHTTPResponse(http.StatusOK, fhttp.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Length":   []string{fmt.Sprint(len(compressedBody))},
			"Content-Type":     []string{"text/plain"},
		}, bytes.NewReader(compressedBody)), nil
	})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	response := recorder.Result()
	defer func() {
		require.NoError(t, response.Body.Close())
	}()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "gzip", response.Header.Get("Content-Encoding"))
	assert.Equal(t, fmt.Sprint(len(compressedBody)), response.Header.Get("Content-Length"))
	assert.Equal(t, compressedBody, body)

	reader, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	decompressedBody, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	assert.Equal(t, "compressed response", string(decompressedBody))
}

func TestHelloStreamsUpstreamResponse(t *testing.T) {
	firstChunkWritten := make(chan struct{})
	allowSecondChunk := make(chan struct{})
	responseBodyReader, responseBodyWriter := io.Pipe()

	handler := &proxy{
		mainURL:       "http://example.test",
		userAgent:     "gotlsproxy-test",
		timeout:       10,
		upstreamProxy: "",
		newHTTPClient: func() (*fhttp.Client, error) {
			return &fhttp.Client{Transport: roundTripFunc(func(_ *fhttp.Request) (*fhttp.Response, error) {
				go func() {
					_, err := responseBodyWriter.Write([]byte("first"))
					require.NoError(t, err)
					close(firstChunkWritten)
					<-allowSecondChunk
					_, err = responseBodyWriter.Write([]byte("second"))
					require.NoError(t, err)
					require.NoError(t, responseBodyWriter.Close())
				}()
				return &fhttp.Response{
					Status:        "200 OK",
					StatusCode:    http.StatusOK,
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        fhttp.Header{"Content-Type": []string{"text/plain"}},
					Body:          responseBodyReader,
					ContentLength: -1,
				}, nil
			})}, nil
		},
	}

	recorder := newLockedResponseRecorder()
	handlerDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		close(handlerDone)
	}()

	<-firstChunkWritten

	require.Eventually(t, func() bool {
		return recorder.BodyString() == "first"
	}, time.Second, 10*time.Millisecond)

	select {
	case <-handlerDone:
		close(allowSecondChunk)
		t.Fatal("handler completed before upstream stream completed")
	default:
	}

	close(allowSecondChunk)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler did not complete after upstream stream completed")
	}
	assert.Equal(t, http.StatusOK, recorder.Code())
	assert.Equal(t, "firstsecond", recorder.BodyString())
}

func TestHeaderNamesSet(t *testing.T) {
	var headers headerNames

	require.NoError(t, headers.Set(" Keep-Alive "))
	require.NoError(t, headers.Set("X-Debug"))

	assert.Equal(t, "Keep-Alive,X-Debug", headers.String())
	assert.Equal(t, map[string]struct{}{
		"keep-alive": {},
		"x-debug":    {},
	}, headers.allowList())
}

func TestHeaderNamesSetRejectsEmptyName(t *testing.T) {
	var headers headerNames

	require.Error(t, headers.Set(" "))
	assert.Empty(t, headers)
}

func TestLoadMITMCA(t *testing.T) {
	_, _, certPEM, keyPEM := generateTestCA(t)
	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	cert, signer, err := loadMITMCA(certPath, keyPath)

	require.NoError(t, err)
	require.True(t, cert.IsCA)
	require.NotNil(t, signer)
}

func TestMITMCertificateSignsHostCertificate(t *testing.T) {
	ca, key, _, _ := generateTestCA(t)
	handler := &proxy{
		mitmCA:     ca,
		mitmSigner: key,
	}

	cert, err := handler.mitmCertificate("target.example")
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.Len(t, cert.Certificate, 2)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, []string{"target.example"}, leaf.DNSNames)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName: "target.example",
		Roots:   roots,
	})
	require.NoError(t, err)

	cached, err := handler.mitmCertificate("target.example")
	require.NoError(t, err)
	assert.Same(t, cert, cached)
}

func TestScrapflyJA3Smoke(t *testing.T) {
	if os.Getenv("GOTLSPROXY_SCRAPFLY_SMOKE") != "1" {
		t.Skip("set GOTLSPROXY_SCRAPFLY_SMOKE=1 to run Scrapfly JA3 smoke test")
	}

	handler := &proxy{
		timeout:       30,
		printErrors:   true,
		upstreamProxy: "",
	}

	server := httptest.NewServer(handler)
	defer server.Close()

	client := &http.Client{Timeout: 45 * time.Second}

	directFingerprint := fetchScrapflyJA3(t, client, scrapflyJA3Endpoint+"/api/fp/ja3")

	fingerprints := []smokeFingerprint{
		{
			name:         "firefox-linux",
			userAgent:    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
			ja3:          "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
			ciphers:      "4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10",
			extensions:   "0-23-65281-10-11-35-16-5-51-43-13-45-28",
			supported:    "29-23-24-25-256-257",
			pointFormats: "0",
		},
		{
			name:         "firefox-macos",
			userAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
			ja3:          "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
			ciphers:      "4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10",
			extensions:   "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037",
			supported:    "29-23-24-25-256-257",
			pointFormats: "0",
		},
	}

	for i := range fingerprints {
		fingerprint := &fingerprints[i]

		t.Run(fingerprint.name+"/ja3", func(t *testing.T) {
			handler.mainURL = scrapflyJA3Endpoint
			handler.userAgent = fingerprint.userAgent
			handler.ja3 = fingerprint.ja3

			proxiedFingerprint := fetchScrapflyJA3(t, client, server.URL+"/api/fp/ja3")
			fingerprint.reportedJA3 = proxiedFingerprint.JA3
			fingerprint.reportedJA3MD = proxiedFingerprint.JA3Digest

			assert.NotEqual(t, directFingerprint.JA3Digest, proxiedFingerprint.JA3Digest)

			// Scrapfly currently omits the TLS version and some ignored extensions from ja3.
			// The remaining parts should still reflect the configured CycleTLS fingerprint.
			ja3Parts := strings.Split(proxiedFingerprint.JA3, ",")
			require.Len(t, ja3Parts, 5)
			assert.Equal(t, fingerprint.ciphers, ja3Parts[1])
			assert.Equal(t, fingerprint.extensions, ja3Parts[2])
			assert.Equal(t, fingerprint.supported, ja3Parts[3])
			assert.Equal(t, fingerprint.pointFormats, ja3Parts[4])
		})

		t.Run(fingerprint.name+"/user-agent", func(t *testing.T) {
			handler.mainURL = userAgentEchoEndpoint
			handler.userAgent = fingerprint.userAgent
			handler.ja3 = fingerprint.ja3

			assert.Equal(t, fingerprint.userAgent, fetchUserAgent(t, client, server.URL+"/user-agent"))
		})
	}

	require.NotEqual(t, fingerprints[0].reportedJA3, fingerprints[1].reportedJA3)
	require.NotEqual(t, fingerprints[0].reportedJA3MD, fingerprints[1].reportedJA3MD)
}
