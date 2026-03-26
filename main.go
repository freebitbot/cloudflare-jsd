package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/t14raptor/go-fast/generator"
	"github.com/t14raptor/go-fast/parser"
	"github.com/t14raptor/go-fast/transform/simplifier"
	"github.com/xkiian/cloudflare-jsd/jsd"
	"github.com/xkiian/cloudflare-jsd/visitors/deobf"
	"github.com/xkiian/cloudflare-jsd/visitors/extract"
)

var (
	flagURL    = flag.String("url", "", "Target URL with Cloudflare challenge")
	flagFile   = flag.String("file", "", "Local JS file to process (offline mode)")
	flagOutput = flag.String("output", "out.js", "Output file for offline mode")
	flagHost   = flag.String("host", "", "Host header (auto-extracted from URL if empty)")
)

func processLocalFile(inputPath, outputPath string) {
	file, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}
	src := string(file)

	ast, err := parser.ParseFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing file: %v\n", err)
		os.Exit(1)
	}

	deobf.UnrollMaps(ast)
	deobf.SequenceUnroller(ast)
	callee := deobf.ReplaceReassignments(ast)
	deobf.ReplaceStrings(ast, callee)
	deobf.ConcatStrings(ast)
	simplifier.Simplify(ast, false)

	err = os.WriteFile(outputPath, []byte(generator.Generate(ast)), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deobfuscated: %s -> %s\n", inputPath, outputPath)
	ctx := extract.ParseScript(ast)
	fmt.Printf("Extracted: Ve=%s Path=%s Alphabet(len=%d)\n", ctx.Ve, ctx.Path, len(ctx.Alphabet))
}

func fetchExt(targetURL string) (*jsd.Extracted, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"sec-ch-ua":                 {"\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\""},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey:         {"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-encoding", "accept-language", "cookie", "priority"},
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(30),
		tlsclient.WithClientProfile(profiles.Chrome_133),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithDisableHttp3(),
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls client: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return jsd.ExtractRT(string(body)), nil
}

func main() {
	flag.Parse()

	// Validate: need either -url or -file, but not both
	if *flagURL == "" && *flagFile == "" {
		fmt.Fprintln(os.Stderr, "Error: either -url or -file flag is required")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  cloudflare-jsd -url <target-url> [-host <host>]")
		fmt.Fprintln(os.Stderr, "  cloudflare-jsd -file <input.js> [-output <output.js>]")
		os.Exit(1)
	}
	if *flagURL != "" && *flagFile != "" {
		fmt.Fprintln(os.Stderr, "Error: cannot use both -url and -file flags")
		os.Exit(1)
	}

	// Offline mode: process local file
	if *flagFile != "" {
		processLocalFile(*flagFile, *flagOutput)
		return
	}

	// Online mode: fetch from URL
	parsedURL, err := url.Parse(*flagURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing URL: %v\n", err)
		os.Exit(1)
	}

	targetHost := *flagHost
	if targetHost == "" {
		targetHost = parsedURL.Host
	}

	ext, err := fetchExt(*flagURL)
	if err != nil {
		panic(err)
	}

	solver, err := jsd.NewSolver(targetHost, *flagURL, ext)
	if err != nil {
		panic(err)
	}

	rawr, err := solver.Run()
	if err != nil {
		panic(err)
	}

	fmt.Println(rawr)
}
