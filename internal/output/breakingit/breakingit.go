package breakingit

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gofrs/uuid/v5"
	"go.k6.io/k6/metrics"
	"go.k6.io/k6/output"
)

// MetricGroup groups samples by timestamp
type MetricGroup struct {
	Timestamp  int64
	Tags       map[string]string
	Values     map[string]float64
	LastUpdate time.Time
	// HTTP error data (only populated when K6_HTTP_ERROR_DATA is enabled)
	ErrorReqHeaders string
	ErrorReqBody    string
	ErrorResHeaders string
	ErrorResBody    string
}

// excludedTags to reduce cardinality
var excludedTags = map[string]bool{
	"proto":               true,
	"tls_version":         true,
	"url":                 true,
	"scenario":            true,
	"expected_response":   true,
	"from_cache":          true,
	"from_prefetch_cache": true,
	"from_service_worker": true,
}

// Retry configuration constants
const (
	maxRetryTimeMs   = 20000 // 20 seconds
	initialBackoffMs = 1100  // Start with 1.1 seconds
	maxBackoffMs     = 5000  // Cap at 5 seconds
)

// Logger writes k6 metric samples to pg-proxy using COPY via multipart batch
type Logger struct {
	out        io.Writer
	proxyURL   string
	database   string
	token      string
	httpClient *http.Client

	// batch buffers
	mu         sync.Mutex
	bufHTTP    *bytes.Buffer
	bufBrowser *bytes.Buffer
	bufVUs     *bytes.Buffer
	bufTrans   *bytes.Buffer
	bufErrors  *bytes.Buffer
	batchTimer *time.Timer
	flushing   bool // flag to prevent recursive flush calls

	// merging state
	pendingGroups     map[int64]*MetricGroup // browser
	pendingHttpGroups map[int64]*MetricGroup // http
	cleanupStop       chan struct{}
	envTags           map[string]string
	customPatterns    map[string]string
	isSynthetic       bool
}

func New(params output.Params) (output.Output, error) {
	// Expect params.ConfigArgument to be pg-proxy base url, e.g. https://proxy/ingest
	base := params.ConfigArgument
	if base == "" {
		return nil, fmt.Errorf("pg-proxy base URL required, e.g. https://host:8080")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid pg-proxy URL: %v", err)
	}
	// Allow env overrides
	db := os.Getenv("PG_PROXY_DB")
	if db == "" {
		db = "breakingit"
	}
	token := os.Getenv("PG_PROXY_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("PG_PROXY_TOKEN is required for Authorization")
	}

	// HTTP client with keep-alive and TLS skip per proxy config
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	// Environment tags from generator
	envTags := make(map[string]string)
	isSynthetic := strings.ToLower(os.Getenv("syntheticMonitoring")) == "true"
	if isSynthetic {
		for _, k := range []string{"nodeName", "location", "scenarioName", "runId"} {
			if v := os.Getenv(k); v != "" {
				envTags[k] = v
			}
		}
	} else {
		for _, k := range []string{"location", "runId", "nodeName", "scenarioName"} {
			if v := os.Getenv(k); v != "" {
				envTags[k] = v
			}
		}
	}
	// normalize snake_case keys expected by DB
	if v, ok := envTags["runId"]; ok {
		envTags["run_id"] = v
	}
	if v, ok := envTags["nodeName"]; ok {
		envTags["node_name"] = v
	}
	if v, ok := envTags["scenarioName"]; ok {
		envTags["scenario_name"] = v
	}

	// Parse CUSTOM_URL_PATTERNS env (pattern==replacement comma-separated)
	customPatterns := make(map[string]string)
	if patterns := os.Getenv("CUSTOM_URL_PATTERNS"); patterns != "" {
		fmt.Fprintf(params.StdOut, "Found CUSTOM_URL_PATTERNS environment variable: %s\n", patterns)
		pairs := strings.Split(patterns, ",")
		for _, pair := range pairs {
			parts := strings.Split(pair, "==")
			if len(parts) == 2 {
				customPatterns[parts[0]] = parts[1]
				fmt.Fprintf(params.StdOut, "Added custom pattern: %s -> %s\n", parts[0], parts[1])
			} else {
				fmt.Fprintf(params.StdOut, "Warning: Invalid pattern format: %s\n", pair)
			}
		}
		fmt.Fprintf(params.StdOut, "Total custom patterns loaded: %d\n", len(customPatterns))
	} else {
		fmt.Fprintf(params.StdOut, "No CUSTOM_URL_PATTERNS environment variable found\n")
	}

	l := &Logger{
		out:               params.StdOut,
		proxyURL:          strings.TrimRight(u.String(), "/"),
		database:          db,
		token:             token,
		httpClient:        client,
		bufHTTP:           &bytes.Buffer{},
		bufBrowser:        &bytes.Buffer{},
		bufVUs:            &bytes.Buffer{},
		bufTrans:          &bytes.Buffer{},
		bufErrors:         &bytes.Buffer{},
		pendingGroups:     make(map[int64]*MetricGroup),
		pendingHttpGroups: make(map[int64]*MetricGroup),
		cleanupStop:       make(chan struct{}),
		envTags:           envTags,
		customPatterns:    customPatterns,
		isSynthetic:       isSynthetic,
	}
	l.batchTimer = time.NewTimer(time.Second)
	go l.batchLoop()
	go l.cleanupProcessor()
	return l, nil
}

func (l *Logger) Description() string { return "breakingit" }
func (l *Logger) Start() error        { return nil }

func (l *Logger) Stop() error {
	l.batchTimer.Stop()
	close(l.cleanupStop)
	l.flush()
	return nil
}

func (l *Logger) batchLoop() {
	for range l.batchTimer.C {
		l.flush()
		if l.isSynthetic {
			l.batchTimer.Reset(5 * time.Second)
		} else {
			l.batchTimer.Reset(time.Second)
		}
	}
}

func (l *Logger) cleanupProcessor() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			now := time.Now()
			toProcess := make([]*MetricGroup, 0)
			toProcessHTTP := make([]*MetricGroup, 0)
			l.mu.Lock()
			for ts, g := range l.pendingGroups {
				if now.Sub(g.LastUpdate) > time.Second {
					toProcess = append(toProcess, g)
					delete(l.pendingGroups, ts)
				}
			}
			for ts, g := range l.pendingHttpGroups {
				if now.Sub(g.LastUpdate) > time.Second {
					toProcessHTTP = append(toProcessHTTP, g)
					delete(l.pendingHttpGroups, ts)
				}
			}
			l.mu.Unlock()
			for _, g := range toProcess {
				l.processBrowserGroup(g)
			}
			for _, g := range toProcessHTTP {
				l.processHttpGroup(g)
			}
		case <-l.cleanupStop:
			return
		}
	}
}

func (l *Logger) flush() {
	l.mu.Lock()
	// Prevent recursive flush calls
	if l.flushing {
		l.mu.Unlock()
		return
	}
	if l.bufHTTP.Len() == 0 && l.bufBrowser.Len() == 0 && l.bufVUs.Len() == 0 && l.bufTrans.Len() == 0 && l.bufErrors.Len() == 0 {
		l.mu.Unlock()
		return
	}

	// Snapshot buffer data and lengths for retry attempts
	bufHTTPSnapshot := make([]byte, l.bufHTTP.Len())
	copy(bufHTTPSnapshot, l.bufHTTP.Bytes())
	bufHTTPLen := l.bufHTTP.Len()
	bufBrowserSnapshot := make([]byte, l.bufBrowser.Len())
	copy(bufBrowserSnapshot, l.bufBrowser.Bytes())
	bufBrowserLen := l.bufBrowser.Len()
	bufVUsSnapshot := make([]byte, l.bufVUs.Len())
	copy(bufVUsSnapshot, l.bufVUs.Bytes())
	bufVUsLen := l.bufVUs.Len()
	bufTransSnapshot := make([]byte, l.bufTrans.Len())
	copy(bufTransSnapshot, l.bufTrans.Bytes())
	bufTransLen := l.bufTrans.Len()
	bufErrorsSnapshot := make([]byte, l.bufErrors.Len())
	copy(bufErrorsSnapshot, l.bufErrors.Bytes())
	bufErrorsLen := l.bufErrors.Len()
	l.flushing = true
	l.mu.Unlock()

	// Build multipart body (reusable for retries)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	if len(bufHTTPSnapshot) > 0 {
		h := make(textproto.MIMEHeader)
		table := "public.requests_raw"
		if l.isSynthetic {
			table = "public.requests_raw_sm"
		}
		h.Set("X-Table", table)
		h.Set("X-Format", "csv")
		pw, _ := mw.CreatePart(h)
		_, _ = io.Copy(pw, bytes.NewReader(bufHTTPSnapshot))
	}
	if len(bufBrowserSnapshot) > 0 {
		h := make(textproto.MIMEHeader)
		table := "public.k6_browser_requests"
		if l.isSynthetic {
			table = "public.k6_browser_requests_sm"
		}
		h.Set("X-Table", table)
		h.Set("X-Format", "csv")
		pw, _ := mw.CreatePart(h)
		_, _ = io.Copy(pw, bytes.NewReader(bufBrowserSnapshot))
	}
	if len(bufVUsSnapshot) > 0 && !l.isSynthetic {
		h := make(textproto.MIMEHeader)
		h.Set("X-Table", "public.virtual_users")
		h.Set("X-Format", "csv")
		pw, _ := mw.CreatePart(h)
		_, _ = io.Copy(pw, bytes.NewReader(bufVUsSnapshot))
	}
	if len(bufTransSnapshot) > 0 {
		h := make(textproto.MIMEHeader)
		table := "public.transactions"
		if l.isSynthetic {
			table = "public.transactions_sm"
		}
		h.Set("X-Table", table)
		h.Set("X-Format", "csv")
		pw, _ := mw.CreatePart(h)
		_, _ = io.Copy(pw, bytes.NewReader(bufTransSnapshot))
	}
	if len(bufErrorsSnapshot) > 0 {
		h := make(textproto.MIMEHeader)
		table := "public.requests_error"
		if l.isSynthetic {
			table = "public.requests_error_sm"
		}
		h.Set("X-Table", table)
		h.Set("X-Format", "csv")
		pw, _ := mw.CreatePart(h)
		_, _ = io.Copy(pw, bytes.NewReader(bufErrorsSnapshot))
	}
	_ = mw.Close()

	// gzip body
	var gzBody bytes.Buffer
	gz := gzip.NewWriter(&gzBody)
	_, _ = gz.Write(body.Bytes())
	_ = gz.Close()

	// Retry logic with exponential backoff
	startTime := time.Now()
	backoffDelay := time.Duration(initialBackoffMs) * time.Millisecond
	attempts := 0
	success := false
	boundary := mw.Boundary()
	gzBodyBytes := gzBody.Bytes()

	for !success && time.Since(startTime) < maxRetryTimeMs*time.Millisecond {
		attempts++
		req, _ := http.NewRequest(http.MethodPost, l.proxyURL+"/ingest/batch", bytes.NewReader(gzBodyBytes))
		req.Header.Set("Authorization", "Bearer "+l.token)
		req.Header.Set("Content-Type", "multipart/mixed; boundary="+boundary)
		req.Header.Set("Content-Encoding", "gzip")

		resp, err := l.httpClient.Do(req)
		if err != nil {
			elapsed := time.Since(startTime)
			if elapsed+backoffDelay < maxRetryTimeMs*time.Millisecond {
				if attempts > 1 {
					fmt.Fprintf(l.out, "pg-proxy ingest request error on attempt %d, retrying in %v: %v\n", attempts, backoffDelay, err)
				}
				time.Sleep(backoffDelay)
				nextBackoffMs := backoffDelay.Milliseconds() * 2
				if nextBackoffMs > maxBackoffMs {
					nextBackoffMs = maxBackoffMs
				}
				backoffDelay = time.Duration(nextBackoffMs) * time.Millisecond
			} else {
				fmt.Fprintf(l.out, "pg-proxy ingest request error after %d attempts (%v elapsed): %v\n", attempts, elapsed, err)
				break
			}
		} else if resp != nil {
			if resp.StatusCode == http.StatusOK {
				success = true
				_ = resp.Body.Close()
				if attempts > 1 {
					fmt.Fprintf(l.out, "pg-proxy ingest succeeded on attempt %d after %v\n", attempts, time.Since(startTime))
				}
			} else {
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				elapsed := time.Since(startTime)
				if elapsed+backoffDelay < maxRetryTimeMs*time.Millisecond {
					if attempts > 1 {
						fmt.Fprintf(l.out, "pg-proxy ingest error status=%d body=%s on attempt %d, retrying in %v\n", resp.StatusCode, string(b), attempts, backoffDelay)
					}
					time.Sleep(backoffDelay)
					nextBackoffMs := backoffDelay.Milliseconds() * 2
					if nextBackoffMs > maxBackoffMs {
						nextBackoffMs = maxBackoffMs
					}
					backoffDelay = time.Duration(nextBackoffMs) * time.Millisecond
				} else {
					fmt.Fprintf(l.out, "pg-proxy ingest error after %d attempts (%v elapsed): status=%d body=%s\n", attempts, elapsed, resp.StatusCode, string(b))
					break
				}
			}
		}
	}

	if !success {
		fmt.Fprintf(l.out, "pg-proxy ingest final failure after %d attempts (%v elapsed)\n", attempts, time.Since(startTime))
	}

	// Reset buffers and check for new data that accumulated during retries
	l.mu.Lock()
	hasNewData := false
	var newHTTPData, newBrowserData, newVUsData, newTransData, newErrorsData []byte

	if success {
		// Check if any buffers grew during retries (new data accumulated)
		// If so, preserve the new data before clearing
		if l.bufHTTP.Len() > bufHTTPLen {
			hasNewData = true
			newHTTPData = make([]byte, l.bufHTTP.Len()-bufHTTPLen)
			copy(newHTTPData, l.bufHTTP.Bytes()[bufHTTPLen:])
		}
		if l.bufBrowser.Len() > bufBrowserLen {
			hasNewData = true
			newBrowserData = make([]byte, l.bufBrowser.Len()-bufBrowserLen)
			copy(newBrowserData, l.bufBrowser.Bytes()[bufBrowserLen:])
		}
		if l.bufVUs.Len() > bufVUsLen {
			hasNewData = true
			newVUsData = make([]byte, l.bufVUs.Len()-bufVUsLen)
			copy(newVUsData, l.bufVUs.Bytes()[bufVUsLen:])
		}
		if l.bufTrans.Len() > bufTransLen {
			hasNewData = true
			newTransData = make([]byte, l.bufTrans.Len()-bufTransLen)
			copy(newTransData, l.bufTrans.Bytes()[bufTransLen:])
		}
		if l.bufErrors.Len() > bufErrorsLen {
			hasNewData = true
			newErrorsData = make([]byte, l.bufErrors.Len()-bufErrorsLen)
			copy(newErrorsData, l.bufErrors.Bytes()[bufErrorsLen:])
		}

		// Clear buffers (we successfully sent the snapshot)
		l.bufHTTP.Reset()
		l.bufBrowser.Reset()
		l.bufVUs.Reset()
		l.bufTrans.Reset()
		l.bufErrors.Reset()

		// Restore new data that accumulated during retries
		if len(newHTTPData) > 0 {
			l.bufHTTP.Write(newHTTPData)
		}
		if len(newBrowserData) > 0 {
			l.bufBrowser.Write(newBrowserData)
		}
		if len(newVUsData) > 0 {
			l.bufVUs.Write(newVUsData)
		}
		if len(newTransData) > 0 {
			l.bufTrans.Write(newTransData)
		}
		if len(newErrorsData) > 0 {
			l.bufErrors.Write(newErrorsData)
		}
	} else {
		// Retry loop exited without success (either timeout or early break), clear buffers to prevent unbounded growth
		l.bufHTTP.Reset()
		l.bufBrowser.Reset()
		l.bufVUs.Reset()
		l.bufTrans.Reset()
		l.bufErrors.Reset()
	}
	l.flushing = false
	l.mu.Unlock()

	// If new data accumulated during retries and we succeeded, flush immediately to send it
	// This ensures no gap in data delivery
	if success && hasNewData {
		// Use a goroutine to avoid blocking and prevent potential deadlock
		go l.flush()
	}
}

func (l *Logger) AddMetricSamples(samples []metrics.SampleContainer) {
	httpMetrics := map[string]bool{
		"http_req_duration":        true,
		"http_req_blocked":         true,
		"http_req_connecting":      true,
		"http_req_tls_handshaking": true,
		"http_req_sending":         true,
		"http_req_waiting":         true,
		"http_req_receiving":       true,
		"http_req_failed":          true,
	}
	browserMetrics := map[string]bool{
		"browser_http_req_duration": true,
		"browser_data_received":     true,
		"browser_http_req_failed":   true,
	}

	for _, sc := range samples {
		for _, s := range sc.GetSamples() {
			ts := s.Time.UnixNano()
			if httpMetrics[s.Metric.Name] {
				l.mu.Lock()
				g, ok := l.pendingHttpGroups[ts]
				if !ok {
					g = &MetricGroup{Timestamp: ts, Tags: map[string]string{}, Values: map[string]float64{}, LastUpdate: time.Now()}
					l.pendingHttpGroups[ts] = g
					copyTagsForHTTP(g.Tags, s.Tags.Map(), l.envTags, l.customPatterns)
				}
				g.Values[s.Metric.Name] = s.Value
				if s.Metric.Name == "http_req_failed" {
					g.ErrorReqHeaders = s.HTTPErrorReqHeaders
					g.ErrorReqBody = s.HTTPErrorReqBody
					g.ErrorResHeaders = s.HTTPErrorResHeaders
					g.ErrorResBody = s.HTTPErrorResBody
				}
				g.LastUpdate = time.Now()
				// If we have all 8 values, process immediately
				if len(g.Values) >= 8 { // 7 numeric + failed bool captured as float
					delete(l.pendingHttpGroups, ts)
					l.mu.Unlock()
					l.processHttpGroup(g)
					continue
				}
				l.mu.Unlock()
				continue
			}
			if browserMetrics[s.Metric.Name] {
				l.mu.Lock()
				g, ok := l.pendingGroups[ts]
				if !ok {
					g = &MetricGroup{Timestamp: ts, Tags: map[string]string{}, Values: map[string]float64{}, LastUpdate: time.Now()}
					l.pendingGroups[ts] = g
					copyTagsForBrowser(g.Tags, s.Tags.Map(), l.envTags, l.customPatterns)
				}
				g.Values[s.Metric.Name] = s.Value
				g.LastUpdate = time.Now()
				if len(g.Values) >= 3 {
					delete(l.pendingGroups, ts)
					l.mu.Unlock()
					l.processBrowserGroup(g)
					continue
				}
				l.mu.Unlock()
				continue
			}
			// pages -> transactions
			if s.Metric.Name == "pages" {
				m := s.Tags.Map()
				// Prefer explicit 'page' tag when available
				pageRaw := fmt.Sprintf("%v", m["page"])
				var transactionName string
				if pageRaw != "" && pageRaw != "<nil>" {
					transactionName = pageRaw
				} else {
					// Derive a stable transaction_name: prefer name, fallback to group, then '/'
					nameRaw := fmt.Sprintf("%v", m["name"])
					if nameRaw == "" || nameRaw == "<nil>" {
						nameRaw = fmt.Sprintf("%v", m["group"]) // sometimes present
					}
					if nameRaw == "" || nameRaw == "<nil>" {
						nameRaw = "/"
					}
					// Process name: if URL, use path; if not URL, use as-is (capped at 64)
					_, _, path, _ := processNameTag(nameRaw, l.customPatterns)
					transactionName = path
				}
				// Non-SM transactions table columns:
				//   time, run_id, location, transaction_name, success, request_size, response_size, response_time
				// SM transactions_sm columns:
				//   time, scenario_name, location, node_name, thread_group_name, transaction_name, success, request_size, response_size, response_time
				isSM := l.isSynthetic
				var row []string
				if isSM {
					row = []string{
						time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
						fmt.Sprintf("%v", l.envTags["scenario_name"]),
						fmt.Sprintf("%v", l.envTags["location"]),
						fmt.Sprintf("%v", l.envTags["node_name"]),
						"", // thread_group_name not applicable for k6 browser pages
						transactionName,
						"true",
						"",
						"",
						fmtInt(s.Value),
					}
				} else {
					row = []string{
						time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
						fmt.Sprintf("%v", l.envTags["run_id"]),
						fmt.Sprintf("%v", l.envTags["location"]),
						transactionName,
						"true",
						"",
						"",
						fmtInt(s.Value),
					}
				}
				l.mu.Lock()
				wt := csv.NewWriter(l.bufTrans)
				_ = wt.Write(row)
				wt.Flush()
				l.mu.Unlock()
				continue
			}
			// k6 http group transactions -> transactions
			if s.Metric.Name == "group_duration" {
				m := s.Tags.Map()
				// Derive transaction_name from 'group' tag, fallback to 'name'
				nameRaw := fmt.Sprintf("%v", m["group"])
				if nameRaw == "" || nameRaw == "<nil>" {
					nameRaw = fmt.Sprintf("%v", m["name"])
				}
				nameRaw = strings.TrimPrefix(nameRaw, "::")
				if nameRaw == "" || nameRaw == "<nil>" {
					nameRaw = "/"
				}
				isSM := l.isSynthetic
				var row []string
				if isSM {
					row = []string{
						time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
						fmt.Sprintf("%v", l.envTags["scenario_name"]),
						fmt.Sprintf("%v", l.envTags["location"]),
						fmt.Sprintf("%v", l.envTags["node_name"]),
						fmt.Sprintf("%v", m["scenario"]), // thread_group_name from k6 scenario
						nameRaw,
						"true",
						"",
						"",
						fmtInt(s.Value),
					}
				} else {
					row = []string{
						time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
						fmt.Sprintf("%v", l.envTags["run_id"]),
						fmt.Sprintf("%v", l.envTags["location"]),
						nameRaw,
						"true",
						"",
						"",
						fmtInt(s.Value),
					}
				}
				l.mu.Lock()
				wt := csv.NewWriter(l.bufTrans)
				_ = wt.Write(row)
				wt.Flush()
				l.mu.Unlock()
				continue
			}
			// vus -> virtual_users (active_threads)
			if s.Metric.Name == "vus" && !l.isSynthetic {
				row := []string{
					time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
					fmt.Sprintf("%v", l.envTags["run_id"]),
					fmt.Sprintf("%v", l.envTags["location"]),
					fmt.Sprintf("%v", l.envTags["node_name"]),
					fmt.Sprintf("%d", int64(s.Value)), // active_threads
					"",                                // started_threads (unknown)
					"",                                // finished_threads (unknown)
				}
				l.mu.Lock()
				wv := csv.NewWriter(l.bufVUs)
				_ = wv.Write(row)
				wv.Flush()
				l.mu.Unlock()
				continue
			}
			// checks -> requests_error(_sm) when value == 0 (failed check)
			if s.Metric.Name == "checks" && s.Value == 0 {
				m := s.Tags.Map()
				checkMsg := m["check"] // e.g. "is status 301"
				if checkMsg == "" {
					checkMsg = "check failed"
				}
				// Derive transaction_name from 'group' tag, strip leading '::'
				transactionName := ""
				if groupVal := m["group"]; groupVal != "" {
					transactionName = strings.TrimPrefix(groupVal, "::")
				}
				responseCode := m["status"] // may be empty
				// Use 'name' tag for sampler_name (this is passed from k6 check tags)
				samplerName := m["name"]
				if samplerName == "" {
					// Fallback to check message or generic name
					samplerName = checkMsg
				}
				// URL can be from 'url' tag or empty
				url := m["url"]
				// Get request/response data and error_response_time if provided via custom tags
				requestData := m["request_data"]
				responseData := m["response_data"]
				responseTime := m["error_response_time"] // response time in ms from check tags
				// Generate UUIDv7 using the measurement timestamp
				id := generateUUIDv7(ts)
				// Build row per schema (includes id field)
				if l.isSynthetic {
					row := []string{
						time.Unix(0, ts).UTC().Format(time.RFC3339Nano), // time
						fmt.Sprintf("%v", l.envTags["scenario_name"]),   // scenario_name
						fmt.Sprintf("%v", l.envTags["location"]),        // location
						fmt.Sprintf("%v", l.envTags["node_name"]),       // node_name
						m["scenario"],   // thread_group_name
						transactionName, // transaction_name
						samplerName,     // sampler_name
						responseCode,    // response_code
						responseTime,    // response_time
						"",              // connection_time
						url,             // url
						"",              // assertions
						checkMsg,        // response_message
						requestData,     // request_headers (used for request data)
						"",              // response_headers
						responseData,    // response_data
						id,              // id (UUIDv7 generated from measurement timestamp)
					}
					l.mu.Lock()
					we := csv.NewWriter(l.bufErrors)
					_ = we.Write(row)
					we.Flush()
					l.mu.Unlock()
				} else {
					row := []string{
						time.Unix(0, ts).UTC().Format(time.RFC3339Nano), // time
						fmt.Sprintf("%v", l.envTags["run_id"]),          // run_id
						fmt.Sprintf("%v", l.envTags["location"]),        // location
						fmt.Sprintf("%v", l.envTags["node_name"]),       // node_name
						transactionName, // transaction_name
						samplerName,     // sampler_name
						responseCode,    // response_code
						responseTime,    // response_time
						"",              // connection_time
						url,             // url
						"",              // assertions
						checkMsg,        // response_message
						requestData,     // request_headers (used for request data)
						"",              // response_headers
						responseData,    // response_data
						id,              // id (UUIDv7 generated from measurement timestamp)
					}
					l.mu.Lock()
					we := csv.NewWriter(l.bufErrors)
					_ = we.Write(row)
					we.Flush()
					l.mu.Unlock()
				}
				continue
			}
			// WebSocket metrics -> requests_raw(_sm)
			if s.Metric.Name == "ws_connecting" || s.Metric.Name == "ws_ping" {
				l.processWebSocketMetric(s, ts)
				continue
			}
			// Custom Trend metrics (custom_*) -> requests_raw(_sm) with minimal schema
			if strings.HasPrefix(s.Metric.Name, "custom_") {
				l.processCustomTrendMetric(s, ts)
				continue
			}
			// removed http_req_failed-specific emission; handled in processHttpGroup when success == false
		}
	}
}

// formatRequestData combines request headers and body into a single string for the request_headers column.
func formatRequestData(headers, body string) string {
	if headers != "" && body != "" {
		return headers + "\n" + body
	}
	if headers != "" {
		return headers
	}
	return body
}

func (l *Logger) processHttpGroup(g *MetricGroup) {
	if g == nil {
		return
	}
	// Map k6 HTTP metrics to requests_raw(_sm) schema
	// Non-SM: time, run_id, location, transaction_name, sampler_name, success, request_size, response_size, response_code, response_connect_time, response_latency, response_time
	// SM:     time, scenario_name, location, node_name, thread_group_name, transaction_name, sampler_name, success, request_size, response_size, response_code, response_connect_time, response_latency, response_time

	// transaction_name comes from group tag; strip leading "::" if present
	transactionName := strings.TrimPrefix(g.Tags["group"], "::")

	// sampler_name: use path (normalized URL path if name was URL, or name itself capped at 64 chars if not)
	samplerName := g.Tags["path"]
	if samplerName == "" {
		// Fallback to name if path somehow missing
		samplerName = g.Tags["name"]
	}

	// success is the inverse of http_req_failed
	success := "true"
	if g.Values["http_req_failed"] != 0 {
		success = "false"
	}

	// response_code from status tag
	responseCode := g.Tags["status"]

	// Timing fields (cast to integer strings) - matching JMeter definitions
	// Note: http_req_duration = sending + waiting + receiving (does NOT include blocked, connecting, or tls_handshaking)
	// See: https://grafana.com/docs/k6/latest/using-k6/metrics/reference/
	connecting := g.Values["http_req_connecting"]
	tlsHandshaking := g.Values["http_req_tls_handshaking"]
	sending := g.Values["http_req_sending"]
	waiting := g.Values["http_req_waiting"]
	duration := g.Values["http_req_duration"]
	// JMeter-style: connectTime = TCP connect + TLS handshake
	connectTime := fmtInt(connecting + tlsHandshaking)
	// JMeter-style: latency = from connect until first byte is received
	latency := fmtInt(connecting + tlsHandshaking + sending + waiting)
	// JMeter-style: responseTime = full time from TCP connect to complete response received
	responseTime := fmtInt(connecting + tlsHandshaking + duration)

	var row []string
	if l.isSynthetic {
		row = []string{
			time.Unix(0, g.Timestamp).UTC().Format(time.RFC3339Nano),
			g.Tags["scenario_name"],
			g.Tags["location"],
			g.Tags["node_name"],
			g.Tags["scenario"], // use k6 scenario tag as thread_group_name
			transactionName,
			samplerName,
			success,
			"", // request_size unknown
			"", // response_size unknown
			responseCode,
			connectTime,
			latency,
			responseTime,
		}
	} else {
		row = []string{
			time.Unix(0, g.Timestamp).UTC().Format(time.RFC3339Nano),
			g.Tags["run_id"],
			g.Tags["location"],
			transactionName,
			samplerName,
			success,
			"", // request_size unknown
			"", // response_size unknown
			responseCode,
			connectTime,
			latency,
			responseTime,
		}
	}
	l.mu.Lock()
	w := csv.NewWriter(l.bufHTTP)
	_ = w.Write(row)
	w.Flush()
	// If not successful, also emit into requests_error(_sm)
	if success == "false" {
		// Build response_message from tags
		errText := fmt.Sprintf("%v", g.Tags["error"]) // may be empty
		if errText == "<nil>" {
			errText = ""
		}
		errMsg := fmt.Sprintf("%v", g.Tags["error_message"])
		if errMsg == "" || errMsg == "<nil>" {
			// fallback to error_code with prefix
			errorCode := fmt.Sprintf("%v", g.Tags["error_code"])
			if errorCode != "" && errorCode != "<nil>" {
				errMsg = fmt.Sprintf("K6 Error code %s", errorCode)
			} else {
				errMsg = ""
			}
		}
		// Construct responseMessage: use errText if available, errMsg if available, or both with " - " separator
		var responseMessage string
		if errText != "" && errMsg != "" {
			responseMessage = fmt.Sprintf("%s - %s", errText, errMsg)
		} else if errText != "" {
			responseMessage = errText
		} else if errMsg != "" {
			responseMessage = errMsg
		} else {
			responseMessage = ""
		}
		responseMessage = strings.TrimSpace(responseMessage)
		nameRaw := g.Tags["name"]
		// samplerName already derived; ensure non-empty
		if samplerName == "" || samplerName == "<nil>" {
			samplerName = transactionName
			if samplerName == "" || samplerName == "<nil>" {
				samplerName = "/"
			}
		}
		// Generate UUIDv7 using the measurement timestamp
		id := generateUUIDv7(g.Timestamp)
		if l.isSynthetic {
			erow := []string{
				time.Unix(0, g.Timestamp).UTC().Format(time.RFC3339Nano),
				g.Tags["scenario_name"],
				g.Tags["location"],
				g.Tags["node_name"],
				g.Tags["scenario"],
				transactionName,
				samplerName,
				responseCode,
				responseTime,
				connectTime,
				nameRaw,
				"",
				responseMessage,
				formatRequestData(g.ErrorReqHeaders, g.ErrorReqBody), // request_headers (includes post payload)
				g.ErrorResHeaders, // response_headers
				g.ErrorResBody,    // response_data
				id,                // id (UUIDv7)
			}
			we := csv.NewWriter(l.bufErrors)
			_ = we.Write(erow)
			we.Flush()
		} else {
			erow := []string{
				time.Unix(0, g.Timestamp).UTC().Format(time.RFC3339Nano),
				g.Tags["run_id"],
				g.Tags["location"],
				g.Tags["node_name"],
				transactionName,
				samplerName,
				responseCode,
				responseTime,
				connectTime,
				nameRaw,
				"",
				responseMessage,
				formatRequestData(g.ErrorReqHeaders, g.ErrorReqBody), // request_headers (includes post payload)
				g.ErrorResHeaders, // response_headers
				g.ErrorResBody,    // response_data
				id,                // id (UUIDv7)
			}
			we := csv.NewWriter(l.bufErrors)
			_ = we.Write(erow)
			we.Flush()
		}
	}
	l.mu.Unlock()
}

func (l *Logger) processBrowserGroup(g *MetricGroup) {
	if g == nil {
		return
	}
	runOrScenario := g.Tags["run_id"]
	isSynthetic := l.isSynthetic
	if isSynthetic {
		runOrScenario = g.Tags["scenario_name"]
	}
	var row []string
	if isSynthetic {
		// k6_browser_requests_sm: time, scenario_name, location, node_name, scheme, hostname, path, name, method, resource_type, status, metrics...
		row = []string{
			time.Unix(0, g.Timestamp).UTC().Format(time.RFC3339Nano),
			runOrScenario,
			g.Tags["location"],
			g.Tags["node_name"],
			g.Tags["scheme"],
			g.Tags["hostname"],
			g.Tags["path"],
			g.Tags["name"],
			g.Tags["method"],
			g.Tags["resource_type"],
			g.Tags["status"],
			fmtFloat(g.Values["browser_http_req_duration"]),
			fmtFloat(g.Values["browser_data_received"]),
			fmtBool(g.Values["browser_http_req_failed"]),
		}
	} else {
		// k6_browser_requests (with run_id and scenario_name fields)
		row = []string{
			time.Unix(0, g.Timestamp).UTC().Format(time.RFC3339Nano),
			runOrScenario,
			g.Tags["location"],
			g.Tags["node_name"],
			g.Tags["scheme"],
			g.Tags["hostname"],
			g.Tags["path"],
			g.Tags["name"],
			g.Tags["method"],
			g.Tags["resource_type"],
			g.Tags["scenario_name"],
			g.Tags["status"],
			fmtFloat(g.Values["browser_http_req_duration"]),
			fmtFloat(g.Values["browser_data_received"]),
			fmtBool(g.Values["browser_http_req_failed"]),
		}
	}
	l.mu.Lock()
	w := csv.NewWriter(l.bufBrowser)
	_ = w.Write(row)
	w.Flush()
	l.mu.Unlock()
}

func (l *Logger) processWebSocketMetric(s metrics.Sample, ts int64) {
	// Process ws_connecting and ws_ping metrics as single-value requests
	m := s.Tags.Map()

	// Extract tags similar to HTTP metrics
	tags := make(map[string]string)
	copyTagsForHTTP(tags, m, l.envTags, l.customPatterns)

	// transaction_name: only set when group tag is present (strip leading "::" if present)
	transactionName := ""
	if groupVal, ok := m["group"]; ok && groupVal != "" {
		transactionName = strings.TrimPrefix(groupVal, "::")
	}

	// sampler_name: derive from name tag (if not URL, capped at 64), else process url tag, else metric name
	var samplerName string
	// Special handling for ws_ping: always use 'WSPing'
	if s.Metric.Name == "ws_ping" {
		samplerName = "WSPing"
	} else {
		// For ws_connecting: prefer name tag (if not URL, capped at 64), else process url tag, else metric name
		nameRaw := m["name"]
		if nameRaw != "" {
			// Check if name is a URL or plain name
			_, _, path, _ := processNameTag(nameRaw, l.customPatterns)
			// If name was a URL, path contains the normalized path; if not, path contains the name (capped at 64)
			samplerName = path
		} else {
			// No name tag, try url tag
			if urlRaw := m["url"]; urlRaw != "" {
				_, _, path, _ := processURL(urlRaw, l.customPatterns)
				if path != "" {
					samplerName = path
				} else {
					samplerName = s.Metric.Name
				}
			} else {
				samplerName = s.Metric.Name
			}
		}
	}

	// response_code from status tag (101 for successful WebSocket connection)
	responseCode := m["status"]
	if responseCode == "" {
		responseCode = "101" // Default to 101 for WebSocket
	}

	// success based on status code (101 = success)
	success := "true"
	if responseCode != "101" {
		success = "false"
	}

	// response_time is the metric value
	responseTime := fmtInt(s.Value)

	var row []string
	if l.isSynthetic {
		// SM: time, scenario_name, location, node_name, thread_group_name, transaction_name, sampler_name, success, request_size, response_size, response_code, response_connect_time, response_latency, response_time
		row = []string{
			time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
			tags["scenario_name"],
			tags["location"],
			tags["node_name"],
			tags["scenario"], // thread_group_name
			transactionName,
			samplerName,
			success,
			"", // request_size
			"", // response_size
			responseCode,
			"", // response_connect_time
			"", // response_latency
			responseTime,
		}
	} else {
		// Non-SM: time, run_id, location, transaction_name, sampler_name, success, request_size, response_size, response_code, response_connect_time, response_latency, response_time
		row = []string{
			time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
			tags["run_id"],
			tags["location"],
			transactionName,
			samplerName,
			success,
			"", // request_size
			"", // response_size
			responseCode,
			"", // response_connect_time
			"", // response_latency
			responseTime,
		}
	}
	l.mu.Lock()
	w := csv.NewWriter(l.bufHTTP)
	_ = w.Write(row)
	w.Flush()
	l.mu.Unlock()
}

func (l *Logger) processCustomTrendMetric(s metrics.Sample, ts int64) {
	// Process custom_* Trend metrics with minimal schema
	m := s.Tags.Map()

	// Extract basic tags from envTags (already normalized to snake_case)
	tags := make(map[string]string)
	for k, v := range l.envTags {
		tags[k] = v
	}

	// transaction_name: only set when group tag is present (strip leading "::" if present)
	transactionName := ""
	if groupVal, ok := m["group"]; ok && groupVal != "" {
		transactionName = strings.TrimPrefix(groupVal, "::")
	}

	// sampler_name: use 'name' tag if present (process as URL or plain name), otherwise metric name
	var samplerName string
	nameRaw := m["name"]
	if nameRaw != "" {
		// Check if name is a URL or plain name
		_, _, path, _ := processNameTag(nameRaw, l.customPatterns)
		// If name was a URL, path contains the normalized path; if not, path contains the name (capped at 64)
		samplerName = path
	} else {
		// Fallback to metric name
		samplerName = s.Metric.Name
	}

	// success: always "true" for custom metrics
	success := "true"

	// response_time is the metric value
	responseTime := fmtInt(s.Value)

	var row []string
	if l.isSynthetic {
		// SM: time, scenario_name, location, node_name, thread_group_name, transaction_name, sampler_name, success, request_size, response_size, response_code, response_connect_time, response_latency, response_time
		row = []string{
			time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
			tags["scenario_name"],
			tags["location"],
			tags["node_name"],
			"", // thread_group_name
			transactionName,
			samplerName,
			success,
			"", // request_size
			"", // response_size
			"", // response_code
			"", // response_connect_time
			"", // response_latency
			responseTime,
		}
	} else {
		// Non-SM: time, run_id, location, transaction_name, sampler_name, success, request_size, response_size, response_code, response_connect_time, response_latency, response_time
		row = []string{
			time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
			tags["run_id"],
			tags["location"],
			transactionName,
			samplerName,
			success,
			"", // request_size
			"", // response_size
			"", // response_code
			"", // response_connect_time
			"", // response_latency
			responseTime,
		}
	}
	l.mu.Lock()
	w := csv.NewWriter(l.bufHTTP)
	_ = w.Write(row)
	w.Flush()
	l.mu.Unlock()
}

func fmtFloat(v float64) string { return fmt.Sprintf("%v", v) }
func fmtBool(v float64) string {
	if v != 0 {
		return "true"
	}
	return "false"
}

func fmtInt(v float64) string { return fmt.Sprintf("%d", int64(v)) }

// generateUUIDv7 generates a UUIDv7 using the provided timestamp (nanoseconds since Unix epoch)
func generateUUIDv7(timestampNanos int64) string {
	// Convert nanoseconds to time.Time for the UUID generator
	t := time.Unix(0, timestampNanos)

	// Create a UUIDv7 with the specific timestamp
	// UUIDv7 format: 48-bit timestamp (ms) + 4-bit version + 12-bit rand_a + 2-bit variant + 62-bit rand_b
	timestampMs := uint64(t.UnixMilli())

	// Build UUID bytes manually with the correct timestamp
	var uuidBytes [16]byte

	// First 48 bits: timestamp in milliseconds (big-endian)
	uuidBytes[0] = byte(timestampMs >> 40)
	uuidBytes[1] = byte(timestampMs >> 32)
	uuidBytes[2] = byte(timestampMs >> 24)
	uuidBytes[3] = byte(timestampMs >> 16)
	uuidBytes[4] = byte(timestampMs >> 8)
	uuidBytes[5] = byte(timestampMs)

	// Generate random bytes for the rest
	randBytes := make([]byte, 10)
	rand.Read(randBytes)

	// Bytes 6-7: version (7) in high nibble + random
	uuidBytes[6] = (0x70) | (randBytes[0] & 0x0F) // Version 7
	uuidBytes[7] = randBytes[1]

	// Bytes 8-15: variant (10) in high 2 bits + random
	uuidBytes[8] = (0x80) | (randBytes[2] & 0x3F) // Variant 10
	copy(uuidBytes[9:], randBytes[3:])

	u, _ := uuid.FromBytes(uuidBytes[:])
	return u.String()
}

// URL parsing, returns scheme, host, path, cleanURL
func processURL(raw string, customPatterns map[string]string) (string, string, string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", raw
	}
	scheme := u.Scheme
	host := u.Hostname()
	p := u.Path
	if p == "" {
		p = "/"
	}
	uuidPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	p = uuidPattern.ReplaceAllString(p, "{uuid}")
	hexPattern := regexp.MustCompile(`[0-9a-f]{12,}`)
	p = hexPattern.ReplaceAllString(p, "{hex}")
	for pattern, replacement := range customPatterns {
		re := regexp.MustCompile(pattern)
		p = re.ReplaceAllString(p, replacement)
	}
	cleanURL := fmt.Sprintf("%s://%s%s", scheme, host, p)
	return scheme, host, p, cleanURL
}

// truncateUTF8 safely truncates a string to maxRunes characters without breaking UTF-8 sequences
func truncateUTF8(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes])
}

// processNameTag processes the "name" tag: if it's a URL, parse and return path; otherwise return as-is (capped at 64 chars)
func processNameTag(nameRaw string, customPatterns map[string]string) (string, string, string, string) {
	// Try to parse as URL
	u, err := url.Parse(nameRaw)
	if err != nil || u.Scheme == "" {
		// Not a valid URL, use as-is but cap at 64 chars (rune-safe)
		nameRaw = truncateUTF8(nameRaw, 64)
		return "", "", nameRaw, nameRaw
	}
	// Valid URL - extract path (without query string)
	scheme := u.Scheme
	host := u.Hostname()
	p := u.Path
	if p == "" {
		p = "/"
	}
	// Apply normalization patterns
	uuidPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	p = uuidPattern.ReplaceAllString(p, "{uuid}")
	hexPattern := regexp.MustCompile(`[0-9a-f]{12,}`)
	p = hexPattern.ReplaceAllString(p, "{hex}")
	for pattern, replacement := range customPatterns {
		re := regexp.MustCompile(pattern)
		p = re.ReplaceAllString(p, replacement)
	}
	cleanURL := fmt.Sprintf("%s://%s%s", scheme, host, p)
	return scheme, host, p, cleanURL
}

func copyTagsForHTTP(dst map[string]string, tags map[string]string, env map[string]string, customPatterns map[string]string) {
	// start with env tags
	for k, v := range env {
		if !excludedTags[k] {
			// map snake_case for consistency
			if k == "nodeName" {
				dst["node_name"] = v
				continue
			}
			if k == "scenarioName" {
				dst["scenario_name"] = v
				continue
			}
			if k == "runId" {
				dst["run_id"] = v
				continue
			}
			dst[k] = v
		}
	}
	// name -> derive host/path (if URL) or use as-is (if not URL, capped at 64 chars)
	if name, ok := tags["name"]; ok {
		nameStr := fmt.Sprintf("%v", name)
		scheme, host, path, clean := processNameTag(nameStr, customPatterns)
		dst["name"] = clean
		if scheme != "" {
			// It was a URL, store scheme and hostname
			dst["hostname"] = host
			dst["path"] = path
		} else {
			// It was not a URL, path contains the name (capped at 64)
			dst["path"] = path
		}
	}
	for k, v := range tags {
		if !excludedTags[k] {
			// preserve normalized fields
			if k == "name" || k == "path" || k == "hostname" || k == "scheme" {
				continue
			}
			dst[k] = fmt.Sprintf("%v", v)
		}
	}
	// Explicitly include k6 'scenario' tag for use as thread_group_name in SM HTTP
	if v, ok := tags["scenario"]; ok {
		dst["scenario"] = fmt.Sprintf("%v", v)
	}
}

func copyTagsForBrowser(dst map[string]string, tags map[string]string, env map[string]string, customPatterns map[string]string) {
	for k, v := range env {
		if !excludedTags[k] {
			if k == "nodeName" {
				dst["node_name"] = v
				continue
			}
			if k == "scenarioName" {
				dst["scenario_name"] = v
				continue
			}
			if k == "runId" {
				dst["run_id"] = v
				continue
			}
			dst[k] = v
		}
	}
	if name, ok := tags["name"]; ok {
		nameStr := fmt.Sprintf("%v", name)
		scheme, host, path, clean := processNameTag(nameStr, customPatterns)
		dst["name"] = clean
		if scheme != "" {
			// It was a URL, store scheme, hostname, and path
			dst["scheme"] = scheme
			dst["hostname"] = host
			dst["path"] = path
		} else {
			// It was not a URL, path contains the name (capped at 64)
			dst["path"] = path
		}
	}
	for k, v := range tags {
		if !excludedTags[k] {
			// preserve normalized fields
			if k == "name" || k == "path" || k == "hostname" || k == "scheme" {
				continue
			}
			dst[k] = fmt.Sprintf("%v", v)
		}
	}
}

func normalizeRegex(p string) string {
	// Translate common PCRE shorthands to Go RE2 equivalents
	replacer := strings.NewReplacer(
		"\\d", "[0-9]",
		"\\D", "[^0-9]",
		"\\w", "[A-Za-z0-9_]",
		"\\W", "[^A-Za-z0-9_]",
		"\\s", "[ \t\r\n\f]",
		"\\S", "[^ \t\r\n\f]",
	)
	return replacer.Replace(p)
}
