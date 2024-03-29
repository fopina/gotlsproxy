package main

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	"github.com/stretchr/testify/assert"
)

func TestPrintIfErrorCode200(t *testing.T) {
	var buf bytes.Buffer
	log.SetFlags(0)
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	var response = cycletls.Response{
		RequestID: "1",
		Status:    200,
		Body:      "test",
		Headers:   nil,
	}
	printIfErrorCode(nil, &response)
	assert.Equal(t, "", buf.String())
}

func TestPrintIfErrorCode400(t *testing.T) {
	var buf bytes.Buffer
	log.SetFlags(0)
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	var response = cycletls.Response{
		RequestID: "1",
		Status:    404,
		Body:      `not found`,
		Headers:   nil,
	}
	printIfErrorCode(nil, &response)
	assert.Equal(t, `Response status 404
== request ==
<nil>
== response ==
{1 404 not found map[] [] }
`, buf.String())
}

func TestCleanErrorResponseBody(t *testing.T) {
	// random 404: curl https://www.google.com/asdasdasd
	var raw = `<!DOCTYPE html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="initial-scale=1, minimum-scale=1, width=device-width">
<title>Error 404 (Not Found)!!1</title>
<style>
*{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}
</style>
<script src="wtv">alert(123)</script>
<a href=//www.google.com/><span id=logo aria-label=Google></span></a>
<p><b>404.</b> <ins>That’s an error.</ins>
<p>The requested URL <code>/asdasdasd</code> was not found on this server.  <ins>That’s all we know.</ins>`
	var cleanError = cleanErrorResponseBody(raw)
	assert.Equal(t, `
Error 404 (Not Found)!!1
404. That’s an error.
The requested URL /asdasdasd was not found on this server.  That’s all we know.`, cleanError)
}
