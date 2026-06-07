package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

	recorder := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		close(handlerDone)
	}()

	<-firstChunkWritten

	require.Eventually(t, func() bool {
		return recorder.Body.String() == "first"
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
	assert.Equal(t, "firstsecond", recorder.Body.String())
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
