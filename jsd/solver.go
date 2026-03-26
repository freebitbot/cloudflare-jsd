package jsd

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/iancoleman/orderedmap"
	"github.com/xkiian/cloudflare-jsd/visitors/deobf"
	"github.com/xkiian/cloudflare-jsd/visitors/extract"
)

type Extracted struct {
	r string
	t string
}
type JsdSolver struct {
	client      tlsclient.HttpClient
	host        string
	uri         string
	ctx         *extract.Ctx
	ext         *Extracted
	fingerprint *orderedmap.OrderedMap
}

func NewSolver(targetURL, uri string, ext *Extracted, profile profiles.ClientProfile, fingerprint *orderedmap.OrderedMap) (*JsdSolver, error) {
	jar := tlsclient.NewCookieJar()

	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(30),
		tlsclient.WithClientProfile(profile),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithDisableHttp3(),
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls client: %w", err)
	}

	return &JsdSolver{
		client:      client,
		host:        strings.TrimSuffix(targetURL, "/"),
		uri:         uri,
		ext:         ext,
		fingerprint: fingerprint,
	}, nil
}

func (s *JsdSolver) FetchScript() (*string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/cdn-cgi/challenge-platform/scripts/jsd/main.js", s.host), nil)
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {"\"Windows\""},
		"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"},
		"sec-ch-ua":          {"\"Chromium\";v=\"146\", \"Google Chrome\";v=\"146\", \"Not;A=Brand\";v=\"99\""},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey:  {"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie"},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	res := string(body)

	return &res, nil
}

func decodeTimestamp(t string) int64 {
	decoded, _ := base64.StdEncoding.DecodeString(t)
	var ts int64
	fmt.Sscanf(string(decoded), "%d", &ts)
	return ts
}

func (s *JsdSolver) Submit() (string, error) {
	payload := orderedmap.New()
	payload.Set("t", decodeTimestamp(s.ext.t))
	payload.Set("lhr", "about:blank")
	payload.Set("api", false)
	payload.Set("payload", s.fingerprint)

	jsonB, err := payload.MarshalJSON()
	if err != nil {
		return "", err
	}
	json := string(jsonB)
	json = strings.Replace(json, "\n", "", -1)

	//fmt.Println(json)

	compressed := Compress(json, s.ctx.Alphabet)

	endpoint := fmt.Sprintf("https://%s/cdn-cgi/challenge-platform/h/%s/jsd/oneshot%s%s",
		s.host, s.ctx.Ve, s.ctx.Path, s.ext.r)
	fmt.Println(endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(compressed))
	if err != nil {
		return "", err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {"\"Windows\""},
		"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"},
		"sec-ch-ua":          {"\"Chromium\";v=\"146\", \"Google Chrome\";v=\"146\", \"Not;A=Brand\";v=\"99\""},
		"content-type":       {"text/plain;charset=UTF-8"},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"origin":             {fmt.Sprintf("https://%s", s.host)},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey:  {"content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie", "priority"},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	fmt.Println(resp.Cookies())
	return "", nil
}

func (s *JsdSolver) Run() (string, error) {
	script, err := s.FetchScript()
	if err != nil {
		return "", err
	}

	s.ctx, err = deobf.DeobfuscateAndExtract(script)
	if err != nil {
		return "", err
	}

	fmt.Println(s.ctx)
	fmt.Println(s.ext)

	s.Submit()
	return "", nil
}
