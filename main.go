// kalshi is a zero-dependency CLI for the Kalshi trade-api/v2.
//
// It signs every request with the account's RSA private key (RSA-PSS / SHA256,
// salt length = digest) exactly as Kalshi requires, talks to the live demo or
// production host, and gates all order-placing commands behind explicit flags.
//
// Build:  go build -o kalshi.exe        (or cross-compile, see README)
// Usage:  kalshi <command> [args] [flags]
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	prodBase  = "https://api.elections.kalshi.com"
	demoBase  = "https://external-api.demo.kalshi.co"
	apiPrefix = "/trade-api/v2"
)

// ---------- config & credentials ----------

type Config struct {
	KeyID      string `json:"keyId"`
	PemPath    string `json:"pemPath"`
	DefaultEnv string `json:"defaultEnv"`
}

func loadConfig(override string) (*Config, error) {
	candidates := []string{}
	if override != "" {
		candidates = append(candidates, override)
	}
	if env := os.Getenv("KALSHI_CONFIG"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, "kalshi.config.json")
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "kalshi.config.json"))
	}
	var firstErr error
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var c Config
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		if c.KeyID == "" || c.PemPath == "" {
			return nil, fmt.Errorf("%s: keyId and pemPath are required", p)
		}
		return &c, nil
	}
	return nil, fmt.Errorf("no kalshi.config.json found (looked in: %s): %v",
		strings.Join(candidates, ", "), firstErr)
}

func loadKey(pemPath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", pemPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: not a valid PEM file", pemPath)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("private key is not RSA")
	}
	return nil, fmt.Errorf("%s: could not parse RSA private key (PKCS#1 or PKCS#8)", pemPath)
}

// ---------- signing ----------

func sign(key *rsa.PrivateKey, method, path string) (ts, sig string, err error) {
	ts = strconv.FormatInt(time.Now().UnixMilli(), 10)
	digest := sha256.Sum256([]byte(ts + method + path)) // path must exclude query string
	raw, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", "", err
	}
	return ts, base64.StdEncoding.EncodeToString(raw), nil
}

// ---------- HTTP client ----------

type Client struct {
	base  string
	keyID string
	key   *rsa.PrivateKey
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// do signs and sends a request. endpoint is relative to apiPrefix (e.g. "/portfolio/balance").
func (c *Client) do(method, endpoint string, query url.Values, body any) ([]byte, error) {
	path := apiPrefix + endpoint // signed path: no query string
	full := c.base + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, full, reader)
	if err != nil {
		return nil, err
	}
	ts, sig, err := sign(c.key, method, path)
	if err != nil {
		return nil, fmt.Errorf("signing request: %w", err)
	}
	req.Header.Set("KALSHI-ACCESS-KEY", c.keyID)
	req.Header.Set("KALSHI-ACCESS-TIMESTAMP", ts)
	req.Header.Set("KALSHI-ACCESS-SIGNATURE", sig)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// getUnsigned fetches a public endpoint without auth (used by `status`).
func getUnsigned(base, endpoint string) ([]byte, error) {
	resp, err := httpClient.Get(base + apiPrefix + endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// ---------- common flags ----------

type common struct {
	prod, demo, confirm, raw bool
	config                   string
}

func addCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.BoolVar(&c.prod, "prod", false, "use PRODUCTION (real money). Default is demo")
	fs.BoolVar(&c.demo, "demo", false, "use demo environment (default)")
	fs.BoolVar(&c.confirm, "confirm", false, "actually send write requests (otherwise dry-run)")
	fs.BoolVar(&c.raw, "raw", false, "print raw JSON response")
	fs.StringVar(&c.config, "config", "", "path to kalshi.config.json")
	return c
}

func (c *common) env(def string) string {
	switch {
	case c.prod:
		return "prod"
	case c.demo:
		return "demo"
	case def != "":
		return def
	default:
		return "demo"
	}
}

func baseFor(env string) string {
	if env == "prod" {
		return prodBase
	}
	return demoBase
}

func newClient(c *common) (*Client, string, error) {
	cfg, err := loadConfig(c.config)
	if err != nil {
		return nil, "", err
	}
	key, err := loadKey(cfg.PemPath)
	if err != nil {
		return nil, "", err
	}
	env := c.env(cfg.DefaultEnv)
	return &Client{base: baseFor(env), keyID: cfg.KeyID, key: key}, env, nil
}

// ---------- helpers ----------

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// parseArgs parses flags that may be interspersed with positional args
// (Go's flag package otherwise stops at the first positional). Returns the
// positional arguments in order.
func parseArgs(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return pos
}

func printJSON(data []byte) {
	var v any
	if json.Unmarshal(data, &v) == nil {
		out, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Println(string(data))
}

func clientOrderID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "kalshi-cli-" + hex.EncodeToString(b)
}

func dollars(cents int) string { return fmt.Sprintf("$%.2f", float64(cents)/100) }

// centsFromDollars parses Kalshi's "0.8700" dollar strings into integer cents.
func centsFromDollars(s string) int {
	f, _ := strconv.ParseFloat(s, 64)
	return int(math.Round(f * 100))
}

// num parses Kalshi's fractional "_fp" strings (sizes, volume) into a float.
func num(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// ---------- commands ----------

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	c := addCommon(fs)
	parseArgs(fs, args)
	env := c.env("")
	data, err := getUnsigned(baseFor(env), "/exchange/status")
	if err != nil {
		die(err)
	}
	fmt.Printf("[%s] %s\n", strings.ToUpper(env), baseFor(env))
	printJSON(data)
}

func cmdBalance(args []string) {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	c := addCommon(fs)
	parseArgs(fs, args)
	cl, env, err := newClient(c)
	if err != nil {
		die(err)
	}
	data, err := cl.do("GET", "/portfolio/balance", nil, nil)
	if err != nil {
		die(err)
	}
	if c.raw {
		printJSON(data)
		return
	}
	var b struct {
		Balance int `json:"balance"`
	}
	json.Unmarshal(data, &b)
	fmt.Printf("[%s] balance: %s\n", strings.ToUpper(env), dollars(b.Balance))
}

func cmdMarkets(args []string) {
	fs := flag.NewFlagSet("markets", flag.ExitOnError)
	c := addCommon(fs)
	series := fs.String("series", "", "filter by series_ticker")
	event := fs.String("event", "", "filter by event_ticker")
	status := fs.String("status", "open", "market status: unopened|open|closed|settled")
	grep := fs.String("grep", "", "case-insensitive substring filter on ticker/title")
	limit := fs.Int("limit", 100, "max markets to fetch")
	parseArgs(fs, args)
	cl, _, err := newClient(c)
	if err != nil {
		die(err)
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(*limit))
	if *status != "" {
		q.Set("status", *status)
	}
	if *series != "" {
		q.Set("series_ticker", *series)
	}
	if *event != "" {
		q.Set("event_ticker", *event)
	}
	data, err := cl.do("GET", "/markets", q, nil)
	if err != nil {
		die(err)
	}
	if c.raw {
		printJSON(data)
		return
	}
	var r struct {
		Markets []struct {
			Ticker    string `json:"ticker"`
			Title     string `json:"title"`
			YesBid    string `json:"yes_bid_dollars"`
			YesAsk    string `json:"yes_ask_dollars"`
			LastPrice string `json:"last_price_dollars"`
			Volume    string `json:"volume_fp"`
		} `json:"markets"`
	}
	json.Unmarshal(data, &r)
	g := strings.ToLower(*grep)
	n := 0
	for _, m := range r.Markets {
		if g != "" && !strings.Contains(strings.ToLower(m.Ticker+" "+m.Title), g) {
			continue
		}
		fmt.Printf("%-34s  yes %2d/%-2d¢  last %2d¢  vol %-9.0f  %s\n",
			m.Ticker, centsFromDollars(m.YesBid), centsFromDollars(m.YesAsk),
			centsFromDollars(m.LastPrice), num(m.Volume), m.Title)
		n++
	}
	fmt.Printf("\n%d markets shown.\n", n)
}

func cmdQuote(args []string) {
	fs := flag.NewFlagSet("quote", flag.ExitOnError)
	c := addCommon(fs)
	pos := parseArgs(fs, args)
	if len(pos) < 1 {
		die(errors.New("usage: kalshi quote <ticker>"))
	}
	cl, _, err := newClient(c)
	if err != nil {
		die(err)
	}
	data, err := cl.do("GET", "/markets/"+pos[0], nil, nil)
	if err != nil {
		die(err)
	}
	if c.raw {
		printJSON(data)
		return
	}
	var r struct {
		Market struct {
			Ticker    string `json:"ticker"`
			Title     string `json:"title"`
			Status    string `json:"status"`
			YesBid    string `json:"yes_bid_dollars"`
			YesAsk    string `json:"yes_ask_dollars"`
			LastPrice string `json:"last_price_dollars"`
			Volume    string `json:"volume_fp"`
			OpenInt   string `json:"open_interest_fp"`
		} `json:"market"`
	}
	json.Unmarshal(data, &r)
	m := r.Market
	fmt.Printf("%s  (%s)\n%s\n", m.Ticker, m.Status, m.Title)
	fmt.Printf("  YES bid/ask: %d¢ / %d¢   last: %d¢\n",
		centsFromDollars(m.YesBid), centsFromDollars(m.YesAsk), centsFromDollars(m.LastPrice))
	fmt.Printf("  volume: %.0f   open interest: %.0f\n", num(m.Volume), num(m.OpenInt))
}

func cmdBook(args []string) {
	fs := flag.NewFlagSet("book", flag.ExitOnError)
	c := addCommon(fs)
	depth := fs.Int("depth", 10, "order book depth")
	pos := parseArgs(fs, args)
	if len(pos) < 1 {
		die(errors.New("usage: kalshi book <ticker> [--depth N]"))
	}
	ticker := pos[0]
	cl, env, err := newClient(c)
	if err != nil {
		die(err)
	}
	q := url.Values{}
	q.Set("depth", strconv.Itoa(*depth))
	data, err := cl.do("GET", "/markets/"+ticker+"/orderbook", q, nil)
	if err != nil {
		die(err)
	}
	if c.raw {
		printJSON(data)
		return
	}
	var r struct {
		Orderbook struct {
			Yes [][]string `json:"yes_dollars"`
			No  [][]string `json:"no_dollars"`
		} `json:"orderbook_fp"`
	}
	json.Unmarshal(data, &r)
	ladder := func(name string, rows [][]string) int {
		// each row is [price_dollars, size_fp] as strings; sort by price descending
		sort.Slice(rows, func(i, j int) bool {
			return centsFromDollars(rows[i][0]) > centsFromDollars(rows[j][0])
		})
		fmt.Printf("  %s book (bids to buy %s):\n", name, name)
		best := 0
		for _, row := range rows {
			if len(row) < 2 {
				continue
			}
			price := centsFromDollars(row[0])
			if best == 0 {
				best = price
			}
			fmt.Printf("    %2d¢ x %.0f\n", price, num(row[1]))
		}
		if len(rows) == 0 {
			fmt.Println("    (empty)")
		}
		return best
	}
	fmt.Printf("[%s] %s order book\n", strings.ToUpper(env), ticker)
	bestYesBid := ladder("YES", r.Orderbook.Yes)
	bestNoBid := ladder("NO", r.Orderbook.No)
	bidStr, askStr := "n/a", "n/a"
	if bestYesBid > 0 {
		bidStr = fmt.Sprintf("%d¢", bestYesBid)
	}
	if bestNoBid > 0 {
		askStr = fmt.Sprintf("%d¢", 100-bestNoBid)
	}
	fmt.Printf("\n  => Best YES bid: %s   Best YES ask: %s\n", bidStr, askStr)
}

func cmdOrders(args []string) {
	fs := flag.NewFlagSet("orders", flag.ExitOnError)
	c := addCommon(fs)
	status := fs.String("status", "resting", "order status: resting|canceled|executed|all")
	parseArgs(fs, args)
	cl, _, err := newClient(c)
	if err != nil {
		die(err)
	}
	q := url.Values{}
	if *status != "" && *status != "all" {
		q.Set("status", *status)
	}
	data, err := cl.do("GET", "/portfolio/orders", q, nil)
	if err != nil {
		die(err)
	}
	printJSON(data)
}

func cmdPositions(args []string) {
	fs := flag.NewFlagSet("positions", flag.ExitOnError)
	c := addCommon(fs)
	parseArgs(fs, args)
	cl, _, err := newClient(c)
	if err != nil {
		die(err)
	}
	data, err := cl.do("GET", "/portfolio/positions", nil, nil)
	if err != nil {
		die(err)
	}
	printJSON(data)
}

type orderReq struct {
	Ticker        string `json:"ticker"`
	ClientOrderID string `json:"client_order_id"`
	Action        string `json:"action"`
	Side          string `json:"side"`
	Count         int    `json:"count"`
	Type          string `json:"type"`
	YesPrice      int    `json:"yes_price,omitempty"`
	NoPrice       int    `json:"no_price,omitempty"`
	BuyMaxCost    int    `json:"buy_max_cost,omitempty"`
}

func placeOrder(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	c := addCommon(fs)
	yes := fs.Bool("yes", false, "trade the YES side (default)")
	no := fs.Bool("no", false, "trade the NO side")
	price := fs.Int("price", 0, "limit price in cents (1-99); required for limit orders")
	otype := fs.String("type", "limit", "order type: limit|market")
	pos := parseArgs(fs, args)
	if len(pos) < 2 {
		die(fmt.Errorf("usage: kalshi %s <ticker> <count> [--yes|--no] [--price ¢] [--type limit|market]", action))
	}
	ticker := pos[0]
	count, err := strconv.Atoi(pos[1])
	if err != nil || count < 1 {
		die(errors.New("count must be a positive integer"))
	}
	side := "yes"
	if *no {
		side = "no"
	}
	if *yes && *no {
		die(errors.New("pass only one of --yes / --no"))
	}
	if *otype == "limit" && (*price < 1 || *price > 99) {
		die(errors.New("limit orders need --price between 1 and 99 (cents)"))
	}

	ord := orderReq{
		Ticker:        ticker,
		ClientOrderID: clientOrderID(),
		Action:        action,
		Side:          side,
		Count:         count,
		Type:          *otype,
	}
	if *otype == "limit" {
		if side == "yes" {
			ord.YesPrice = *price
		} else {
			ord.NoPrice = *price
		}
	} else if action == "buy" {
		// market buy requires a spending cap; cap at the theoretical max ($1/contract).
		ord.BuyMaxCost = count * 100
	}

	cl, env, err := newClient(c)
	if err != nil {
		die(err)
	}
	mode := "DRY-RUN"
	if c.confirm {
		mode = "LIVE"
	}
	body, _ := json.MarshalIndent(ord, "", "  ")
	fmt.Printf("======== ENV=%s  MODE=%s ========\n", strings.ToUpper(env), mode)
	fmt.Printf("POST %s%s/portfolio/orders\n%s\n", baseFor(env), apiPrefix, string(body))

	if !c.confirm {
		fmt.Println("\n(dry-run) nothing sent. Re-run with --confirm to place this order.")
		if env == "prod" {
			fmt.Println("NOTE: this is PRODUCTION — adding --confirm spends real money.")
		}
		return
	}
	data, err := cl.do("POST", "/portfolio/orders", nil, ord)
	if err != nil {
		die(err)
	}
	fmt.Println("\norder placed:")
	printJSON(data)
}

func cmdCancel(args []string) {
	fs := flag.NewFlagSet("cancel", flag.ExitOnError)
	c := addCommon(fs)
	pos := parseArgs(fs, args)
	if len(pos) < 1 {
		die(errors.New("usage: kalshi cancel <order_id> --confirm"))
	}
	id := pos[0]
	cl, env, err := newClient(c)
	if err != nil {
		die(err)
	}
	if !c.confirm {
		fmt.Printf("[%s] DRY-RUN: would DELETE /portfolio/orders/%s\nRe-run with --confirm to cancel.\n",
			strings.ToUpper(env), id)
		return
	}
	data, err := cl.do("DELETE", "/portfolio/orders/"+id, nil, nil)
	if err != nil {
		die(err)
	}
	fmt.Println("canceled:")
	printJSON(data)
}

func usage() {
	fmt.Print(`kalshi — direct CLI for Kalshi trade-api/v2

Read (safe):
  status                       exchange status (no auth)
  balance                      account balance (auth smoke test)
  markets [--series|--event|--status|--grep|--limit]   list/filter markets
  book <ticker> [--depth N]    order book
  quote <ticker>               last price / bid / ask / volume
  orders [--status resting]    your orders
  positions                    your positions

Write (gated: dry-run unless --confirm; demo unless --prod):
  buy  <ticker> <count> [--yes|--no] [--price ¢] [--type limit|market]
  sell <ticker> <count> [--yes|--no] [--price ¢] [--type limit|market]
  cancel <order_id>

Global flags: --prod  --demo  --confirm  --raw  --config <path>

Examples:
  kalshi status
  kalshi balance --prod
  kalshi book KXLOLMAP-26JUN282300KCT1-3-T1 --prod
  kalshi buy KXLOLMAP-26JUN282300KCT1-3-T1 1 --yes --price 78 --prod         # dry-run
  kalshi buy KXLOLMAP-26JUN282300KCT1-3-T1 1 --yes --price 78 --prod --confirm # LIVE
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "status":
		cmdStatus(args)
	case "balance":
		cmdBalance(args)
	case "markets":
		cmdMarkets(args)
	case "book":
		cmdBook(args)
	case "quote":
		cmdQuote(args)
	case "orders":
		cmdOrders(args)
	case "positions":
		cmdPositions(args)
	case "buy":
		placeOrder("buy", args)
	case "sell":
		placeOrder("sell", args)
	case "cancel":
		cmdCancel(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage()
		os.Exit(1)
	}
}
