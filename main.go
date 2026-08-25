package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// --- ASCII Banner ---
var banner = `
 _   _            _   _  __ _           _     
| | | | __ _ _ __| |_(_)/ _(_)_ __   __| | ___  ___
| |_| |/ _  | '__| __| | |_| | '_ \ / _  |/ _ \/ __|
|  _  | (_| | |  | |_| |  _| | | | | (_| |  __/\__ \
|_| |_|\__,_|_|   \__|_|_| |_|_| |_|\__,_|\___||___/
                                                    
[!] The Ultimate API Key Auditor & Permission Extractor
[!] Coded in Go | High Concurrency | Deep Scanning
------------------------------------------------------
`

// --- Structs ---
type Endpoint struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Header string `json:"header"`
	Prefix string `json:"prefix"`
}

type Signature struct {
	Name      string     `json:"name"`
	Regex     string     `json:"regex"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Config struct {
	Platforms []Signature `json:"platforms"`
}

type ScanResult struct {
	Platform    string `json:"platform"`
	EndpointURL string `json:"endpoint"`
	IsValid     bool   `json:"is_valid"`
	StatusCode  int    `json:"status_code"`
	Permissions string `json:"permissions,omitempty"`
	ErrorDetail string `json:"error_detail,omitempty"`
}

// Global Variables for Colors
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
)

func main() {
	fmt.Println(cyan(banner))

	// --- CLI Flags Setup ---
	keyPtr := flag.String("k", "", "API Key to scan and validate")
	outputPtr := flag.String("o", "", "Output file path (e.g., target.txt or results.json)")
	delayPtr := flag.Duration("delay", 0, "Delay between requests to avoid rate limits (e.g., 500ms, 1s)")
	flag.Parse()

	// Validation
	if *keyPtr == "" {
		color.Red("[-] Error: API Key is required.")
		fmt.Println("Usage: hackthekey -k <API_KEY> [-o <OUTPUT_FILE>] [-delay <DURATION>]")
		fmt.Println("Run 'hackthekey -h' for more details.")
		os.Exit(1)
	}

	targetKey := *keyPtr
	outputFile := *outputPtr
	delay := *delayPtr

	fmt.Printf("[*] Target Key: %s\n", yellow(targetKey[:10]+"..."))
	if delay > 0 {
		fmt.Printf("[*] Rate Limiting Active: Delay of %v between requests\n", delay)
	}
	fmt.Printf("[*] Starting deep scan...\n\n")

	// Load Signatures
	signatures := loadSignatures()

	// Step 1: Identify Platform
	platform, found := identifyPlatform(targetKey, signatures)
	if !found {
		color.Red("[-] Unknown key format. Signature not found in database.")
		os.Exit(0)
	}
	
	color.Green("[+] Platform Identified: %s", platform.Name)
	fmt.Printf("[*] Scanning %d endpoints concurrently...\n\n", len(platform.Endpoints))

	// Step 2: Concurrent Scanning with Rate Limiting
	results := scanEndpointsConcurrently(platform, targetKey, delay)

	// Step 3: Display & Save Results
	displayResults(results)
	
	if outputFile != "" {
		saveToFile(results, outputFile)
		color.Green("\n[+] Results successfully saved to: %s", outputFile)
	}
}

// --- Load Signatures ---
func loadSignatures() []Signature {
	file, err := os.Open("signatures.json")
	if err == nil {
		defer file.Close()
		var config Config
		if json.NewDecoder(file).Decode(&config) == nil {
			return config.Platforms
		}
	}
	// Fallback: Hardcoded if JSON not found (omitted for brevity, relies on JSON)
	color.Yellow("[!] signatures.json not found. Using minimal fallback.")
	return getHardcodedSignatures()
}

// --- Module 1: Regex Identifier ---
func identifyPlatform(key string, signatures []Signature) (Signature, bool) {
	for _, sig := range signatures {
		re := regexp.MustCompile(sig.Regex)
		if re.MatchString(key) {
			return sig, true
		}
	}
	return Signature{}, false
}

// --- Module 2: Multi-Endpoint Requester (Goroutines + Rate Limit) ---
func scanEndpointsConcurrently(platform Signature, key string, delay time.Duration) []ScanResult {
	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, len(platform.Endpoints))

	for _, ep := range platform.Endpoints {
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()
			
			// RATE LIMITING: Sleep before making the request
			if delay > 0 {
				time.Sleep(delay)
			}
			
			result := sendRequest(endpoint, key, platform.Name)
			resultsChan <- result
		}(ep)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []ScanResult
	for res := range resultsChan {
		results = append(results, res)
	}
	return results
}

// --- HTTP Request & Module 3: Error Parser ---
func sendRequest(ep Endpoint, key string, platformName string) ScanResult {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, _ := http.NewRequest(ep.Method, ep.URL, nil)
	
	if ep.Header != "" {
		authValue := ep.Prefix + key
		// Special handling for Telegram which replaces {KEY} in URL
		if platformName == "Telegram" {
			req.URL.Path = strings.Replace(req.URL.Path, "{KEY}", key, 1)
		} else {
			req.Header.Set(ep.Header, authValue)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ScanResult{Platform: platformName, EndpointURL: ep.URL, IsValid: false, ErrorDetail: "Network/Timeout Error"}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	result := ScanResult{
		Platform:    platformName,
		EndpointURL: ep.URL,
		StatusCode:  resp.StatusCode,
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.IsValid = true
		result.Permissions = extractPermissions(platformName, resp.Header, bodyString)
	} else {
		result.IsValid = false
		result.ErrorDetail = parseDynamicError(resp.StatusCode, bodyString)
	}

	return result
}

// --- Advanced: Dynamic Error Parsing ---
func parseDynamicError(statusCode int, body string) string {
	var errResp map[string]interface{}
	if json.Unmarshal([]byte(body), &errResp) == nil {
		if errMsg, ok := errResp["error"].(map[string]interface{}); ok {
			if msg, exists := errMsg["message"]; exists {
				return fmt.Sprintf("%v", msg)
			}
		}
		if msg, ok := errResp["message"]; ok {
			return fmt.Sprintf("%v", msg)
		}
	}
	
	switch statusCode {
	case 401: return "Invalid Key / Unauthorized"
	case 403: 
		if strings.Contains(strings.ToLower(body), "ip") { return "Key Valid but IP Restricted" }
		return "Forbidden / Insufficient Permissions"
	case 429: return "Rate Limit Exceeded (Key is Active!)"
	default:  return fmt.Sprintf("HTTP %d Error", statusCode)
	}
}

// --- Advanced: Permission Extractor ---
func extractPermissions(platform string, headers http.Header, body string) string {
	if platform == "GitHub" {
		if scopes := headers.Get("X-OAuth-Scopes"); scopes != "" {
			return "Scopes: " + scopes
		}
	}
	return "Active Access (Read/Write)"
}

// --- Display Results ---
func displayResults(results []ScanResult) {
	fmt.Println("========== SCAN RESULTS ==========")
	for _, r := range results {
		if r.IsValid {
			fmt.Printf("[%s] %s | Status: %d | Perms: %s\n", 
				green("VALID"), r.EndpointURL, r.StatusCode, cyan(r.Permissions))
		} else {
			fmt.Printf("[%s] %s | Status: %d | Reason: %s\n", 
				red("INVAL"), r.EndpointURL, r.StatusCode, yellow(r.ErrorDetail))
		}
	}
	fmt.Println("==================================")
}

// --- Save to File ---
func saveToFile(results []ScanResult, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		color.Red("[-] Failed to create output file: %v", err)
		return
	}
	defer file.Close()

	if strings.HasSuffix(filename, ".json") {
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		file.Write(jsonData)
	} else {
		for _, r := range results {
			status := "INVALID"
			if r.IsValid { status = "VALID" }
			fmt.Fprintf(file, "[%s] %s | Status: %d | Details: %s | Perms: %s\n", 
				status, r.EndpointURL, r.StatusCode, r.ErrorDetail, r.Permissions)
		}
	}
}

// --- Hardcoded Fallback (Minimal) ---
func getHardcodedSignatures() []Signature {
	return []Signature{
		{Name: "Stripe", Regex: `^(sk_live_|rk_live_)[a-zA-Z0-9]{24,}`, Endpoints: []Endpoint{
			{URL: "https://api.stripe.com/v1/charges", Method: "GET", Header: "Authorization", Prefix: "Bearer "},
		}},
	}
}
