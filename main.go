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
	flagURL         = flag.String("url", "", "Target URL with Cloudflare challenge")
	flagFile        = flag.String("file", "", "Local JS file to process (offline mode)")
	flagOutput      = flag.String("output", "out.js", "Output file for offline mode")
	flagHost        = flag.String("host", "", "Host header (auto-extracted from URL if empty)")
	flagDownload    = flag.String("download", "", "Download challenge script to file (requires -url)")
	flagProfile     = flag.String("profile", "chrome_146", "Browser TLS profile (chrome_146, chrome_146_psk, firefox_148, safari_ios_18_0, etc.)")
	flagFingerprint = flag.String("fingerprint", "", "Path to fingerprint JSON file (optional, uses built-in if empty)")
)

func getProfile(name string) profiles.ClientProfile {
	if p, ok := profiles.MappedTLSClients[name]; ok {
		return p
	}
	fmt.Fprintf(os.Stderr, "Warning: unknown profile '%s', using chrome_146\n", name)
	return profiles.MappedTLSClients["chrome_146"]
}

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

func downloadScript(targetURL, outputPath string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing URL: %v\n", err)
		os.Exit(1)
	}

	ext, err := fetchExt(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching page: %v\n", err)
		os.Exit(1)
	}

	// Load or generate fingerprint
	fp, err := jsd.GenerateFingerprint(parsedURL.Host, targetURL, *flagFingerprint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading fingerprint: %v\n", err)
		os.Exit(1)
	}

	solver, err := jsd.NewSolver(parsedURL.Host, targetURL, ext, getProfile(*flagProfile), fp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating solver: %v\n", err)
		os.Exit(1)
	}

	script, err := solver.FetchScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching script: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outputPath, []byte(*script), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Downloaded: https://%s/cdn-cgi/challenge-platform/scripts/jsd/main.js -> %s\n", parsedURL.Host, outputPath)
}

func fetchExt(targetURL string) (*jsd.Extracted, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"sec-ch-ua":                 {"\"Chromium\";v=\"146\", \"Google Chrome\";v=\"146\", \"Not;A=Brand\";v=\"99\""},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {"\"Windows\""},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {"en-US,en;q=0.9"},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey:         {"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-encoding", "accept-language", "cookie", "priority"},
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(30),
		tlsclient.WithClientProfile(getProfile(*flagProfile)),
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

	// Download mode: requires -url and -download
	if *flagDownload != "" {
		if *flagURL == "" {
			fmt.Fprintln(os.Stderr, "Error: -download requires -url flag")
			os.Exit(1)
		}
		downloadScript(*flagURL, *flagDownload)
		return
	}

	// Validate: need either -url or -file, but not both
	if *flagURL == "" && *flagFile == "" {
		fmt.Fprintln(os.Stderr, "Error: either -url or -file flag is required")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  cloudflare-jsd -url <target-url> [-host <host>]")
		fmt.Fprintln(os.Stderr, "  cloudflare-jsd -url <target-url> -download <output.js>")
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

	// Load or generate fingerprint
	fp, err := jsd.GenerateFingerprint(targetHost, *flagURL, *flagFingerprint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading fingerprint: %v\n", err)
		os.Exit(1)
	}

	solver, err := jsd.NewSolver(targetHost, *flagURL, ext, getProfile(*flagProfile), fp)
	if err != nil {
		panic(err)
	}

	rawr, err := solver.Run()
	if err != nil {
		panic(err)
	}

	fmt.Println(rawr)
}
