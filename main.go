package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
)

var version string = "DEV"

var mainURL string
var userAgent string
var ja3 string
var listenAddress string
var timeout int
var printErrors bool
var upstreamProxy string

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	_, errWrite := w.Write([]byte(err.Error()))
	if errWrite != nil {
		log.Printf("ERROR Proxy2Client: %v", errWrite)
	}
}

var htmlTagStripper = regexp.MustCompile(`<.*?>`)
var htmlStyleScriptStripper = regexp.MustCompile(`(?s)<(style|script)\b.*>(.*?)</(style|script)>`)
var newlineStripper = regexp.MustCompile(`(?s)\n+`)

func cleanErrorResponseBody(body string) string {
	return newlineStripper.ReplaceAllString(
		htmlTagStripper.ReplaceAllString(
			htmlStyleScriptStripper.ReplaceAllString(body, ""),
			"",
		),
		"\n",
	)
}

func printIfErrorCode(request *http.Request, response *cycletls.Response) {
	if response.Status >= 400 {
		log.Printf("Response status %d", response.Status)
		log.Printf("== request ==")
		log.Printf("%v", request)
		log.Printf("== response ==")
		log.Printf("%v", cycletls.Response{RequestID: response.RequestID, Status: response.Status, Body: cleanErrorResponseBody(response.Body), Headers: response.Headers})
	}
}

func copyResponseHeaders(dst http.Header, src map[string]string) {
	for name, value := range src {
		switch {
		case strings.EqualFold(name, "Content-Encoding"):
			continue
		case strings.EqualFold(name, "Content-Length"):
			continue
		}

		dst.Add(name, value)
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

func copyRequestHeaders(src http.Header) map[string]string {
	forwardedHeaders := make(map[string]string)
	connectionHeaders := requestConnectionHeaders(src)

	for name, values := range src {
		headerName := strings.ToLower(name)
		if strings.EqualFold(name, "User-Agent") {
			continue
		}
		if _, ok := hopByHopRequestHeaders[headerName]; ok {
			continue
		}
		if _, ok := connectionHeaders[headerName]; ok {
			continue
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

func hello(w http.ResponseWriter, req *http.Request) {
	client := cycletls.Init()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeError(w, err)
		return
	}

	response, err := client.Do(fmt.Sprintf("%s%s", mainURL, req.URL), cycletls.Options{
		Body:      string(body),
		Ja3:       ja3,
		UserAgent: userAgent,
		Headers:   copyRequestHeaders(req.Header),
		Timeout:   timeout,
		Proxy:     upstreamProxy,
	}, req.Method)
	if err != nil {
		writeError(w, err)
		return
	}

	if printErrors {
		printIfErrorCode(req, &response)
	}

	copyResponseHeaders(w.Header(), response.Headers)
	w.WriteHeader(response.Status)
	_, err = w.Write([]byte(response.Body))
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
