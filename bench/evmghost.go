// Command evmghost is a Go port of the quick recon pass.
//
// Same pipeline as the Rust binary and the Python reference: bytecode fetch,
// proxy resolution, dispatcher selector extraction, named views, storage
// reads. The named views are probed concurrently — Go's whole point — so the
// benchmark measures the language and its RPC layer rather than any
// dependency graph. Stdlib only.
//
// Usage:
//
//	go run ./bench/evmghost.go <RPC_URL> <ADDRESS> [deep]
package main

import (
	"math/big"

	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
const (
	eip1967ImplSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	eip1822Slot     = "0xc5f16f0fcc639fa48a354c50895b9d8f8c1a5d0d0a1c9e2f0e3a6b8c7d6e5f4a"
)

// Views worth naming inline: the highest-value reads when planning an attack.
var namedViews = map[string]string{
	"0x8da5cb5b": "owner()",
	"0x5c975abb": "paused()",
	"0x18160ddd": "totalSupply()",
	"0x06fdde03": "name()",
	"0x95d89b41": "symbol()",
	"0x313ce567": "decimals()",
}

// writeOpcodes: an SSTORE or a CREATE/CALL family opcode anywhere in the
// dispatcher region means some path can mutate state.
var writeOpcodes = map[byte]bool{
	0x55: true, // SSTORE
	0xf0: true, // CREATE
	0xf1: true, // CALL
	0xf2: true, // CALLCODE
	0xf4: true, // DELEGATECALL
	0xf5: true, // CREATE2
	0xfa: true, // STATICCALL
}

type rpc struct {
	urls   []string
	cur    int
	client *http.Client
	mu     sync.Mutex // guards the request id counter and cur
	id     int
}

var rpcPool = []string{
	"https://ethereum-rpc.publicnode.com",
	"https://ethereum.publicnode.com",
	"https://1rpc.io/eth",
	"https://eth.drpc.org",
}

func newRPC(urls ...string) *rpc {
	pool := rpcPool
	if len(urls) > 0 {
		pool = urls
	}
	// The default transport pools only 2 idle connections per host. With six
	// concurrent named-view calls the goroutines contend for those two slots
	// and dial the rest fresh, which makes "concurrent" slower than sequential.
	// Size the pool to the actual fan-out.
	return &rpc{
		urls:   pool,
		client: &http.Client{Timeout: 60 * time.Second, Transport: pooledTransport()},
	}
}

func pooledTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
	}
}

type rpcResp struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// call issues one JSON-RPC request, rotating to the next endpoint on failure.
// Public endpoints rate-limit aggressively; a probe keeps rotating until one
// answers rather than dying on the first 429 or reset.
func (r *rpc) call(method string, params ...any) (json.RawMessage, error) {
	var lastErr error
	for i := 0; i < len(r.urls); i++ {
		r.mu.Lock()
		url := r.urls[r.cur]
		r.id++
		id := r.id
		r.mu.Unlock()

		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  method,
			"params":  params,
		})
		if err != nil {
			return nil, err
		}

		resp, err := r.client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = fmt.Errorf("POST %s: %w", method, err)
			r.rotate()
			continue
		}

		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read body: %w", err)
			r.rotate()
			continue
		}

		var out rpcResp
		if err := json.Unmarshal(raw, &out); err != nil {
			lastErr = fmt.Errorf("parse json: %w", err)
			r.rotate()
			continue
		}
		if len(out.Error) > 0 && string(out.Error) != "null" {
			lastErr = fmt.Errorf("%s: %s", method, out.Error)
			r.rotate()
			continue
		}
		return out.Result, nil
	}
	return nil, lastErr
}

func (r *rpc) rotate() {
	r.mu.Lock()
	r.cur = (r.cur + 1) % len(r.urls)
	r.mu.Unlock()
}

func (r *rpc) code(addr string) ([]byte, error) {
	raw, err := r.call("eth_getCode", addr, "latest")
	if err != nil {
		return nil, err
	}
	var hexstr string
	if err := json.Unmarshal(raw, &hexstr); err != nil {
		return nil, err
	}
	if hexstr == "0x" {
		return nil, nil
	}
	return hex.DecodeString(hexstr[2:])
}

func (r *rpc) storageAt(addr string, slot *big.Int) (string, error) {
	raw, err := r.call("eth_getStorageAt", addr, "0x"+slot.Text(16), "latest")
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(raw, &s)
}

func (r *rpc) blockNumber() (int64, error) {
	raw, err := r.call("eth_blockNumber")
	if err != nil {
		return 0, err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	return strconv.ParseInt(s[2:], 16, 64)
}

func (r *rpc) callView(to, data string) (string, error) {
	raw, err := r.call("eth_call", map[string]string{"to": to, "data": data}, "latest")
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(raw, &s)
}

// loadSignatures reads the 289k-selector dataset once. Named views win so the
// inline labels are correct even where the raw corpus is bare hex.
func loadSignatures(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, 300_000)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out[line] = "unknown"
	}
	for sel, name := range namedViews {
		out[sel] = name
	}
	return out, nil
}

// extractSelectors walks the Solidity dispatcher and returns every PUSH4 it
// compares. The pattern is CALLDATALOAD(0) SHR(224) <PUSH4 sel> EQ JUMPI, so
// we keep a PUSH4 only when an EQ follows it. Duplicate-free, order-preserving.
func extractSelectors(code []byte) []string {
	out := make([]string, 0, 64)
	seen := make(map[string]struct{})
	for i := 0; i < len(code); {
		op := code[i]
		switch {
		case op == 0x63 && i+5 <= len(code): // PUSH4
			sel := "0x" + hex.EncodeToString(code[i+1:i+5])
			if i+5 < len(code) && code[i+5] == 0x14 { // EQ follows
				if _, ok := seen[sel]; !ok {
					seen[sel] = struct{}{}
					out = append(out, sel)
				}
			}
			i += 5
		case op >= 0x60 && op <= 0x7f: // PUSH1..PUSH32: skip the payload
			i += 1 + int(op-0x5f)
		default:
			i++
		}
	}
	return out
}

// resolveProxy follows an EIP-1967/1822 proxy to its logic contract.
func resolveProxy(r *rpc, addr string) (string, error) {
	for _, slot := range []string{eip1967ImplSlot, eip1822Slot} {
		slotInt := new(big.Int)
		if _, ok := slotInt.SetString(slot[2:], 16); !ok {
			return "", fmt.Errorf("bad slot: %s", slot)
		}
		raw, err := r.storageAt(addr, slotInt)
		if err != nil {
			return "", err
		}
		if len(raw) >= 42 {
			val := raw[len(raw)-40:]
			if val != strings.Repeat("0", 40) {
				return "0x" + val, nil
			}
		}
	}
	return addr, nil
}

type timings struct {
	Code            time.Duration
	Proxy           time.Duration
	SelectorExtract time.Duration
	NamedViews      time.Duration
	Storage         time.Duration
	SignatureLoad   time.Duration
	WriteScan       time.Duration
	ProbeSelectors  time.Duration
}

type result struct {
	Logic     string             `json:"logic"`
	IsProxy   bool               `json:"is_proxy"`
	CodeBytes int                `json:"code_bytes"`
	Selectors int                `json:"selectors"`
	Views     map[string]string  `json:"views"`
	Slots     map[string]string  `json:"slots"`
	WriteOps  int                `json:"write_opcodes"`
	Reachable int                `json:"reachable"`
	Timings   timings            `json:"-"`
	TimingsMS map[string]float64 `json:"timings_ms"`
}

func quick(r *rpc, addr string, sigs map[string]string) (result, error) {
	var res result
	var t0 time.Time

	t0 = time.Now()
	code, err := r.code(addr)
	if err != nil {
		return res, err
	}
	res.Timings.Code = time.Since(t0)

	t0 = time.Now()
	logic, err := resolveProxy(r, addr)
	if err != nil {
		return res, err
	}
	res.Timings.Proxy = time.Since(t0)

	res.Logic = logic
	res.IsProxy = !strings.EqualFold(logic, addr)
	if res.IsProxy {
		code, err = r.code(logic)
		if err != nil {
			return res, err
		}
	}
	res.CodeBytes = len(code)

	t0 = time.Now()
	sels := extractSelectors(code)
	res.Timings.SelectorExtract = time.Since(t0)
	res.Selectors = len(sels)

	// Named views, all in flight at once. This is the whole reason to reach
	// for Go: six round trips collapse into one network latency.
	t0 = time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	views := make(map[string]string, len(namedViews))
	for sel, name := range namedViews {
		wg.Add(1)
		go func(sel, name string) {
			defer wg.Done()
			out, err := r.callView(addr, sel)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				views[name] = "err: " + err.Error()
			} else {
				views[name] = out
			}
		}(sel, name)
	}
	wg.Wait()
	res.Timings.NamedViews = time.Since(t0)
	res.Views = views

	t0 = time.Now()
	slots := make(map[string]string, 5)
	for i := 0; i < 5; i++ {
		s, err := r.storageAt(addr, big.NewInt(int64(i)))
		if err != nil {
			return res, err
		}
		slots[strconv.Itoa(i)] = s
	}
	res.Timings.Storage = time.Since(t0)
	res.Slots = slots
	return res, nil
}

func deep(r *rpc, addr string, sigs map[string]string) (result, error) {
	res, err := quick(r, addr, sigs)
	if err != nil {
		return res, err
	}

	code, err := r.code(res.Logic)
	if err != nil {
		return res, err
	}

	t0 := time.Now()
	writeOps := 0
	for _, b := range code {
		if writeOpcodes[b] {
			writeOps++
		}
	}
	res.Timings.WriteScan = time.Since(t0)
	res.WriteOps = writeOps

	// Probe every selector as a stranger, bounded so a 200-selector contract
	// does not open 200 connections at once.
	t0 = time.Now()
	sels := extractSelectors(code)
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	reachable := 0
	for _, sel := range sels {
		wg.Add(1)
		sem <- struct{}{}
		go func(sel string) {
			defer wg.Done()
			defer func() { <-sem }()
			out, err := r.callView(addr, sel+strings.Repeat("0", 64))
			if err == nil && out != "0x" {
				mu.Lock()
				reachable++
				mu.Unlock()
			}
		}(sel)
	}
	wg.Wait()
	res.Timings.ProbeSelectors = time.Since(t0)
	res.Reachable = reachable
	return res, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: evmghost <RPC_URL> <ADDRESS> [deep]")
		os.Exit(1)
	}
	rpcURL, addr := os.Args[1], os.Args[2]
	mode := "quick"
	if len(os.Args) > 3 {
		mode = os.Args[3]
	}

	// "eth" expands to the public endpoint pool, matching the Rust binary
	var r *rpc
	if rpcURL == "eth" {
		r = newRPC()
	} else {
		r = newRPC(rpcURL)
	}

	sigPath := "../signatures.txt"
	if _, err := os.Stat(sigPath); err != nil {
		sigPath = "signatures.txt"
	}

	t0 := time.Now()
	sigs, err := loadSignatures(sigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signatures: %v\n", err)
		os.Exit(1)
	}
	sigLoad := time.Since(t0)

	t0 = time.Now()
	var res result
	if mode == "deep" {
		res, err = deep(r, addr, sigs)
	} else {
		res, err = quick(r, addr, sigs)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
	total := time.Since(t0)

	res.Timings.SignatureLoad = sigLoad
	res.TimingsMS = map[string]float64{
		"signature_load":   float64(sigLoad.Microseconds()) / 1000,
		"eth_getCode":      float64(res.Timings.Code.Microseconds()) / 1000,
		"proxy_resolve":    float64(res.Timings.Proxy.Microseconds()) / 1000,
		"selector_extract": float64(res.Timings.SelectorExtract.Microseconds()) / 1000,
		"named_views":      float64(res.Timings.NamedViews.Microseconds()) / 1000,
		"storage_0_4":      float64(res.Timings.Storage.Microseconds()) / 1000,
		"write_scan":       float64(res.Timings.WriteScan.Microseconds()) / 1000,
		"probe_selectors":  float64(res.Timings.ProbeSelectors.Microseconds()) / 1000,
		"total":            float64(total.Microseconds()) / 1000,
	}

	fmt.Printf("logic          : %s\n", res.Logic)
	fmt.Printf("proxy          : %t\n", res.IsProxy)
	fmt.Printf("code_bytes     : %d\n", res.CodeBytes)
	fmt.Printf("selectors      : %d\n", res.Selectors)
	fmt.Printf("write_opcodes  : %d\n", res.WriteOps)
	fmt.Printf("reachable      : %d\n", res.Reachable)
	for k, v := range res.TimingsMS {
		fmt.Printf("%-16s: %.1f ms\n", k, v)
	}
}
