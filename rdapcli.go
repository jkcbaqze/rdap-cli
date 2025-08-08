// rdapcli.go
// A self-contained RDAP/WHOIS CLI for Windows (works cross-platform).
// Stdlib-only: no external deps.
// Build: go build -ldflags="-s -w" -o rdapcli.exe rdapcli.go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Version = "1.0.0"

type QueryType int

const (
	QueryUnknown QueryType = iota
	QueryDomain
	QueryIP
	QueryASN
)

type CLIOptions struct {
	Query         string
	Format        string // text|whois|json
	File          bool
	Outfile       string
	API           string // ""|http
	Port          int
	Endpoint      string
	TimeoutSec    int
	Verbose       bool
	VersionOnly   bool
	FallbackWHOIS bool
}

func main() {
	opts := parseFlags()
	if opts.VersionOnly {
		fmt.Println(Version)
		return
	}
	if len(os.Args) == 1 || strings.EqualFold(opts.Format, "help") {
		printHelp()
		return
	}
	// If API server mode:
	if strings.EqualFold(opts.API, "http") {
		if err := runHTTP(opts); err != nil {
			fail(3, "api server error: %v", err)
		}
		return
	}

	if opts.Query == "" {
		fmt.Fprintln(os.Stderr, "error: --query is required (or use --api http)")
		printHelp()
		os.Exit(2)
	}

	// Execute single query flow
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSec)*time.Second)
	defer cancel()

	qtype := classifyQuery(opts.Query)
	rdapURL := buildRDAPURL(opts.Endpoint, opts.Query, qtype)

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "RDAP endpoint: %s\n", rdapURL)
	}

	start := time.Now()
	body, status, err := httpGET(ctx, rdapURL)
	elapsed := time.Since(start)

	if opts.Verbose {
		if err != nil {
			fmt.Fprintf(os.Stderr, "RDAP http error: %v (elapsed %s)\n", err, elapsed)
		} else {
			fmt.Fprintf(os.Stderr, "RDAP http status: %d (elapsed %s)\n", status, elapsed)
		}
	}

	var rdap map[string]any
	rdapOK := false
	if err == nil && status == 200 {
		if e := json.Unmarshal(body, &rdap); e == nil {
			rdapOK = true
		}
	}

	var whoisText string
	if !rdapOK && opts.FallbackWHOIS {
		if opts.Verbose {
			fmt.Fprintln(os.Stderr, "Attempting WHOIS fallback…")
		}
		whoisText, _ = queryWHOISBestEffort(opts.Query, qtype, opts.Verbose, time.Duration(opts.TimeoutSec)*time.Second)
	}

	// Decide output
	var outText string
	switch strings.ToLower(opts.Format) {
	case "json":
		if rdapOK {
			outText = prettyJSON(rdap)
		} else if whoisText != "" {
			// Provide WHOIS in JSON wrapper
			m := map[string]any{"ok": false, "error": "rdap unavailable", "whois": whoisText}
			outText = prettyJSON(m)
		} else {
			fail(4, "no RDAP data and WHOIS fallback disabled or failed")
		}
	case "whois":
		if whoisText != "" {
			outText = whoisText
		} else if rdapOK {
			// Render RDAP in whois-like plaintext
			outText = renderWhoisLikeFromRDAP(rdap)
		} else {
			fail(4, "no data available (rdap and whois)")
		}
	default: // "text"
		if rdapOK {
			outText = renderTextSummary(rdap)
			if whoisText != "" {
				outText += "\n\n# WHOIS Fallback\n" + whoisText
			}
		} else if whoisText != "" {
			outText = "# RDAP unavailable; showing WHOIS fallback\n" + whoisText
		} else {
			fail(4, "no data available (rdap and whois)")
		}
	}

	// Print to stdout
	fmt.Println(outText)

	// Write file if requested
	if opts.File || opts.Outfile != "" {
		path, warn := resolveOutputPath(opts, qtype)
		if warn != "" {
			fmt.Fprintln(os.Stderr, "warning:", warn)
		}
		if err := os.WriteFile(path, []byte(outText), 0644); err != nil {
			fail(5, "write file error: %v", err)
		}
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "Wrote %s\n", path)
		}
	}
}

// --- Flags & Help ---

func parseFlags() CLIOptions {
	var opts CLIOptions
	flag.StringVar(&opts.Query, "query", "", "Domain, IP, or ASN (e.g., example.com, 8.8.8.8, AS13335)")
	flag.BoolVar(&opts.File, "file", false, "Write output to the user's Documents folder with auto filename")
	flag.StringVar(&opts.Outfile, "outfile", "", "Write output to a specific path instead of Documents")
	flag.StringVar(&opts.Format, "format", "text", "Output format: text|whois|json")
	flag.StringVar(&opts.API, "api", "", "Run as API server: http")
	flag.IntVar(&opts.Port, "port", 8080, "API server port (when --api http)")
	flag.StringVar(&opts.Endpoint, "endpoint", "https://rdap.org", "RDAP base endpoint (e.g., https://rdap.org)")
	flag.IntVar(&opts.TimeoutSec, "timeout", 10, "HTTP/WHOIS timeout in seconds")
	flag.BoolVar(&opts.Verbose, "verbose", false, "Verbose diagnostics to stderr")
	flag.BoolVar(&opts.VersionOnly, "version", false, "Print version and exit")
	flag.BoolVar(&opts.FallbackWHOIS, "fallback-whois", false, "If RDAP fails, attempt WHOIS fallback")
	flag.Parse()
	return opts
}

func printHelp() {
	fmt.Println(`rdapcli ` + Version + `
Usage:
  rdapcli --query <domain|ip|asn> [--format text|whois|json] [--file] [--outfile <path>] [--endpoint <url>] [--timeout <sec>] [--verbose] [--fallback-whois]
  rdapcli --api http [--port 8080] [--endpoint <url>] [--timeout <sec>] [--verbose]
  rdapcli --version
  rdapcli --help

Examples:
  rdapcli --query example.com --format text
  rdapcli --query 8.8.8.8 --format json --file
  rdapcli --query AS13335 --format whois --fallback-whois --verbose
  rdapcli --api http --port 8090

Notes:
  * --file writes to the user's Documents folder with an auto name: <query>-yymmdd-hhmm.txt
  * --outfile overrides the destination path explicitly
  * --fallback-whois uses whois.iana.org for referral, then queries the referred server if available
  * Exit codes: 0 ok, 2 invalid args, 3 network/HTTP error, 4 parse/format error, 5 I/O error
`)
}

// --- Classification & URL ---

var reASN = regexp.MustCompile(`^(?i:AS)?\d+$`)

func classifyQuery(q string) QueryType {
	q = strings.TrimSpace(q)
	if ip := net.ParseIP(q); ip != nil {
		return QueryIP
	}
	if reASN.MatchString(q) {
		return QueryASN
	}
	// very lightweight domain guess
	if strings.Contains(q, ".") && !strings.ContainsAny(q, " /\\") {
		return QueryDomain
	}
	return QueryUnknown
}

func normalizeASN(q string) string {
	q = strings.TrimSpace(strings.ToUpper(q))
	return strings.TrimPrefix(q, "AS")
}

func buildRDAPURL(base, q string, t QueryType) string {
	base = strings.TrimRight(base, "/")
	switch t {
	case QueryIP:
		return fmt.Sprintf("%s/ip/%s", base, q)
	case QueryASN:
		return fmt.Sprintf("%s/autnum/%s", base, normalizeASN(q))
	default:
		// Domain as default
		return fmt.Sprintf("%s/domain/%s", base, q)
	}
}

// --- HTTP & JSON ---

func httpGET(ctx context.Context, url string) ([]byte, int, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   0, // governed by ctx
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB cap
	return data, resp.StatusCode, nil
}

func prettyJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// --- Rendering ---

func renderTextSummary(rdap map[string]any) string {
	var b strings.Builder
	get := func(key string) string {
		if v, ok := rdap[key]; ok {
			return fmt.Sprint(v)
		}
		return ""
	}
	fmt.Fprintf(&b, "# RDAP Summary\n")
	if o := get("objectClassName"); o != "" {
		fmt.Fprintf(&b, "Object: %s\n", o)
	}
	if h := get("handle"); h != "" {
		fmt.Fprintf(&b, "Handle: %s\n", h)
	}
	if l := get("ldhName"); l != "" {
		fmt.Fprintf(&b, "LDH Name: %s\n", l)
	}
	if u := get("unicodeName"); u != "" {
		fmt.Fprintf(&b, "Unicode Name: %s\n", u)
	}
	if n := get("name"); n != "" {
		fmt.Fprintf(&b, "Name: %s\n", n)
	}
	if s := sliceOfStrings(rdap["status"]); len(s) > 0 {
		fmt.Fprintf(&b, "Status: %s\n", strings.Join(s, ", "))
	}
	if e := extractEvents(rdap); len(e) > 0 {
		fmt.Fprintf(&b, "Events:\n")
		for _, ev := range e {
			fmt.Fprintf(&b, "  - %s: %s\n", ev.Action, ev.Date)
		}
	}
	if ns := extractNameservers(rdap); len(ns) > 0 {
		fmt.Fprintf(&b, "Nameservers:\n")
		for _, n := range ns {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	if ents := extractEntities(rdap); len(ents) > 0 {
		fmt.Fprintf(&b, "Entities:\n")
		for _, en := range ents {
			fmt.Fprintf(&b, "  - %s [%s]\n", en.Name, strings.Join(en.Roles, ","))
		}
	}
	return b.String()
}

func renderWhoisLikeFromRDAP(rdap map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "RDAP-WHOIS-Style Output\n")
	fmt.Fprintf(&b, "=======================\n")
	writeLine := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%-16s %s\n", k+":", v)
		}
	}
	writeLine("ObjectClass", fmt.Sprint(rdap["objectClassName"]))
	writeLine("Handle", fmt.Sprint(rdap["handle"]))
	writeLine("LDHName", fmt.Sprint(rdap["ldhName"]))
	writeLine("UnicodeName", fmt.Sprint(rdap["unicodeName"]))
	if s := sliceOfStrings(rdap["status"]); len(s) > 0 {
		writeLine("Status", strings.Join(s, ", "))
	}
	for _, ev := range extractEvents(rdap) {
		writeLine("Event-"+ev.Action, ev.Date)
	}
	for _, n := range extractNameservers(rdap) {
		writeLine("NameServer", n)
	}
	for _, en := range extractEntities(rdap) {
		writeLine("Entity", en.Name+" ["+strings.Join(en.Roles, ",")+"]")
	}
	return b.String()
}

func sliceOfStrings(v any) []string {
	var out []string
	if v == nil {
		return out
	}
	switch t := v.(type) {
	case []any:
		for _, it := range t {
			out = append(out, fmt.Sprint(it))
		}
	case []string:
		out = append(out, t...)
	default:
		out = append(out, fmt.Sprint(v))
	}
	return out
}

type Event struct {
	Action string
	Date   string
}

func extractEvents(rdap map[string]any) []Event {
	var out []Event
	ev, ok := rdap["events"].([]any)
	if !ok {
		return out
	}
	for _, e := range ev {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		act := fmt.Sprint(m["eventAction"])
		dat := fmt.Sprint(m["eventDate"])
		if act != "" && dat != "" {
			out = append(out, Event{Action: act, Date: dat})
		}
	}
	return out
}

func extractNameservers(rdap map[string]any) []string {
	var out []string
	ns, ok := rdap["nameservers"].([]any)
	if !ok {
		return out
	}
	for _, n := range ns {
		m, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if l := fmt.Sprint(m["ldhName"]); l != "" {
			out = append(out, l)
			continue
		}
		if u := fmt.Sprint(m["unicodeName"]); u != "" {
			out = append(out, u)
		}
	}
	return out
}

type Entity struct {
	Name  string
	Roles []string
}

func extractEntities(rdap map[string]any) []Entity {
	var out []Entity
	ents, ok := rdap["entities"].([]any)
	if !ok {
		return out
	}
	for _, e := range ents {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		var name string
		if vcard, ok := m["vcardArray"].([]any); ok && len(vcard) == 2 {
			// vCard: ["vcard", [ [ "fn", {}, "text", "Full Name" ], ... ]]
			if arr, ok := vcard[1].([]any); ok {
				for _, fld := range arr {
					rec, ok := fld.([]any)
					if ok && len(rec) >= 4 && fmt.Sprint(rec[0]) == "fn" {
						name = fmt.Sprint(rec[3])
						break
					}
				}
			}
		}
		if name == "" {
			name = fmt.Sprint(m["handle"])
		}
		roles := sliceOfStrings(m["roles"])
		out = append(out, Entity{Name: name, Roles: roles})
	}
	return out
}

// --- Output path ---

func resolveOutputPath(opts CLIOptions, qtype QueryType) (string, string) {
	if opts.Outfile != "" {
		return opts.Outfile, ""
	}
	now := time.Now()
	ts := now.Format("060102-1504")
	base := sanitizeForFilename(opts.Query)
	name := fmt.Sprintf("%s-%s.txt", base, ts)

	// Try %USERPROFILE%\Documents
	if home, _ := os.UserHomeDir(); home != "" {
		p := filepath.Join(home, "Documents", name)
		if exists(filepath.Dir(p)) {
			return p, ""
		}
	}
	// Try %OneDrive%\Documents
	if od := os.Getenv("OneDrive"); od != "" {
		p := filepath.Join(od, "Documents", name)
		if exists(filepath.Dir(p)) {
			return p, ""
		}
	}
	// Fallback: CWD
	return name, "Documents folder not found; wrote to current directory"
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func sanitizeForFilename(s string) string {
	// allow alnum, dot, dash, underscore; replace others with '-'
	return regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(s, "-")
}

// --- WHOIS minimal implementation (no deps) ---

func queryWHOISBestEffort(q string, t QueryType, verbose bool, timeout time.Duration) (string, error) {
	server := ""
	var err error

	switch t {
	case QueryDomain:
		server, err = whoisReferralFromIANA(q, timeout)
		if verbose {
			fmt.Fprintf(os.Stderr, "IANA referral: %s (err=%v)\n", server, err)
		}
		// Fallback for .com/.net
		if server == "" && (strings.HasSuffix(strings.ToLower(q), ".com") || strings.HasSuffix(strings.ToLower(q), ".net")) {
			server = "whois.verisign-grs.com:43"
		}
	case QueryIP, QueryASN:
		// ARIN is commonly fine; better logic would parse allocation, but we keep it simple.
		server = "whois.arin.net:43"
	default:
		// Try IANA anyway
		server, err = whoisReferralFromIANA(q, timeout)
	}

	if server == "" {
		server = "whois.iana.org:43"
	}
	txt, err := whoisQuery(server, q, timeout)
	return txt, err
}

func whoisReferralFromIANA(q string, timeout time.Duration) (string, error) {
	resp, err := whoisQuery("whois.iana.org:43", q, timeout)
	if err != nil {
		return "", err
	}
	// parse "refer: whois.example-registry.tld"
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			srv := strings.TrimSpace(line[len("refer:"):])
			if srv != "" && !strings.Contains(srv, ":") {
				srv = srv + ":43"
			}
			return srv, nil
		}
	}
	return "", errors.New("no referral")
}

func whoisQuery(server string, query string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// Some servers prefer "domain example.com" format; most accept plain query
	_, _ = conn.Write([]byte(query + "\r\n"))
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, conn)
	return buf.String(), nil
}

// --- API server ---

type APIRequest struct {
	Query    string `json:"query"`
	Format   string `json:"format"`   // text|whois|json
	Endpoint string `json:"endpoint"` // optional
	Timeout  int    `json:"timeout"`  // seconds
}

type APIResponse struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Query   string          `json:"query,omitempty"`
	Summary string          `json:"summary,omitempty"` // when format=text/whois
	RDAP    json.RawMessage `json:"rdap,omitempty"`    // when format=json
	WHOIS   string          `json:"whois,omitempty"`
}

func runHTTP(opts CLIOptions) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/rdap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var req APIRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Timeout <= 0 {
			req.Timeout = opts.TimeoutSec
		}
		endpoint := strings.TrimSpace(req.Endpoint)
		if endpoint == "" {
			endpoint = opts.Endpoint
		}
		qtype := classifyQuery(req.Query)
		url := buildRDAPURL(endpoint, req.Query, qtype)

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.Timeout)*time.Second)
		defer cancel()

		body, status, err := httpGET(ctx, url)
		resp := APIResponse{OK: false, Query: req.Query}

		if err == nil && status == 200 {
			switch strings.ToLower(req.Format) {
			case "json":
				resp.OK = true
				resp.RDAP = json.RawMessage(body)
			case "whois":
				var rdap map[string]any
				if e := json.Unmarshal(body, &rdap); e == nil {
					resp.OK = true
					resp.Summary = renderWhoisLikeFromRDAP(rdap)
				}
			default:
				var rdap map[string]any
				if e := json.Unmarshal(body, &rdap); e == nil {
					resp.OK = true
					resp.Summary = renderTextSummary(rdap)
				}
			}
		} else {
			resp.Error = "rdap unavailable"
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
	})

	addr := fmt.Sprintf(":%d", opts.Port)
	s := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "API listening on %s\n", addr)
	}
	return s.ListenAndServe()
}

// --- Utilities ---

func fail(code int, msg string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+msg+"\n", a...)
	os.Exit(code)
}
