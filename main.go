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
	// --- MEGA DATABASE (Directly embedded in main.go) ---
const megaSignaturesJSON = `
{
  "platforms": [
    {"name": "Google Cloud / Firebase", "regex": "AIza[0-9A-Za-z\\-_]{35}", "endpoints": [{"url": "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={KEY}", "method": "POST", "header": "", "prefix": ""}]},
    {"name": "AWS", "regex": "AKIA[0-9A-Z]{16}", "endpoints": [{"url": "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", "method": "GET", "header": "Authorization", "prefix": "AWS4"}]},
    {"name": "Stripe", "regex": "sk_live_[0-9a-zA-Z]{24,34}", "endpoints": [{"url": "https://api.stripe.com/v1/charges", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "GitHub", "regex": "ghp_[0-9a-zA-Z]{36}", "endpoints": [{"url": "https://api.github.com/user", "method": "GET", "header": "Authorization", "prefix": "token "}]},
    {"name": "OpenAI", "regex": "sk-[a-zA-Z0-9]{48}", "endpoints": [{"url": "https://api.openai.com/v1/models", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Slack", "regex": "xox[baprs]-[0-9a-zA-Z\\-]{10,250}", "endpoints": [{"url": "https://slack.com/api/auth.test", "method": "POST", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Twilio", "regex": "SK[0-9a-fA-F]{32}", "endpoints": [{"url": "https://api.twilio.com/2010-04-01/Accounts.json", "method": "GET", "header": "Authorization", "prefix": "Basic "}]},
    {"name": "SendGrid", "regex": "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}", "endpoints": [{"url": "https://api.sendgrid.com/v3/user/profile", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Telegram", "regex": "[0-9]{8,10}:[0-9A-Za-z_-]{35}", "endpoints": [{"url": "https://api.telegram.org/bot{KEY}/getMe", "method": "GET", "header": "", "prefix": ""}]},
    {"name": "DigitalOcean", "regex": "dop_v1_[0-9a-f]{64}", "endpoints": [{"url": "https://api.digitalocean.com/v2/account", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Shopify", "regex": "shpat_[a-fA-F0-9]{32}", "endpoints": [{"url": "https://admin.shopify.com/services/shop", "method": "GET", "header": "X-Shopify-Access-Token", "prefix": ""}]},
    {"name": "GitLab", "regex": "glpat-[0-9a-zA-Z\\-_]{20}", "endpoints": [{"url": "https://gitlab.com/api/v4/user", "method": "GET", "header": "PRIVATE-TOKEN", "prefix": ""}]},
    {"name": "Discord", "regex": "[a-zA-Z0-9_-]{59,68}", "endpoints": [{"url": "https://discord.com/api/v10/users/@me", "method": "GET", "header": "Authorization", "prefix": "Bot "}]},
    {"name": "Cloudflare", "regex": "[a-zA-Z0-9]{37}", "endpoints": [{"url": "https://api.cloudflare.com/client/v4/user/tokens/verify", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Mailgun", "regex": "key-[0-9a-zA-Z]{32}", "endpoints": [{"url": "https://api.mailgun.net/v3/domains", "method": "GET", "header": "Authorization", "prefix": "Basic "}]},
    {"name": "PayPal", "regex": "Access-Token\\.[0-9a-zA-Z\\-_]{40,100}", "endpoints": [{"url": "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Razorpay", "regex": "rzp_(live|test)_[0-9a-zA-Z]{14,20}", "endpoints": [{"url": "https://api.razorpay.com/v1/payments", "method": "GET", "header": "Authorization", "prefix": "Basic "}]},
    {"name": "Heroku", "regex": "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "endpoints": [{"url": "https://api.heroku.com/account", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Vercel", "regex": "[a-zA-Z0-9]{24}", "endpoints": [{"url": "https://api.vercel.com/v2/user", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Netlify", "regex": "[a-zA-Z0-9_-]{40,50}", "endpoints": [{"url": "https://api.netlify.com/api/v1/user", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Anthropic", "regex": "sk-ant-[0-9a-zA-Z\\-_]{40,100}", "endpoints": [{"url": "https://api.anthropic.com/v1/messages", "method": "POST", "header": "x-api-key", "prefix": ""}]},
    {"name": "HuggingFace", "regex": "hf_[0-9a-zA-Z]{34}", "endpoints": [{"url": "https://huggingface.co/api/whoami-v2", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Replicate", "regex": "r8_[0-9a-zA-Z]{32}", "endpoints": [{"url": "https://api.replicate.com/v1/predictions", "method": "GET", "header": "Authorization", "prefix": "Token "}]},
    {"name": "Postmark", "regex": "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "endpoints": [{"url": "https://api.postmarkapp.com/server", "method": "GET", "header": "X-Postmark-Server-Token", "prefix": ""}]},
    {"name": "Bitbucket", "regex": "[0-9a-zA-Z]{18,20}", "endpoints": [{"url": "https://api.bitbucket.org/2.0/user", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Jira", "regex": "[0-9a-zA-Z]{24}", "endpoints": [{"url": "https://api.atlassian.com/me", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "CircleCI", "regex": "[0-9a-fA-F]{40}", "endpoints": [{"url": "https://circleci.com/api/v1.1/me", "method": "GET", "header": "Circle-Token", "prefix": ""}]},
    {"name": "DockerHub", "regex": "dckr_pat_[0-9a-zA-Z\\-_]{27}", "endpoints": [{"url": "https://hub.docker.com/v2/user/", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "npm", "regex": "npm_[0-9a-zA-Z]{36}", "endpoints": [{"url": "https://registry.npmjs.org/-/npm/v1/user", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Supabase", "regex": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[0-9a-zA-Z\\-\\_\\.]+", "endpoints": [{"url": "https://api.supabase.com/v1/projects", "method": "GET", "header": "apikey", "prefix": ""}]},
    {"name": "PlanetScale", "regex": "pscale_pw_[0-9a-zA-Z\\-_]{43}", "endpoints": [{"url": "https://api.planetscale.com/v1/user", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Twitter/X", "regex": "AAAAAAAAAAAAAAAAAAAAA[0-9a-zA-Z%]{30,50}", "endpoints": [{"url": "https://api.twitter.com/2/users/me", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Meta/Facebook", "regex": "EAACEdEose0cBA[0-9A-Za-z]+", "endpoints": [{"url": "https://graph.facebook.com/me?access_token={KEY}", "method": "GET", "header": "", "prefix": ""}]},
    {"name": "LinkedIn", "regex": "[0-9a-z]{12,14}", "endpoints": [{"url": "https://api.linkedin.com/v2/me", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Mailchimp", "regex": "[0-9a-f]{32}-us[0-9]{1,2}", "endpoints": [{"url": "https://us1.api.mailchimp.com/3.0/", "method": "GET", "header": "Authorization", "prefix": "Basic "}]},
    {"name": "Notion", "regex": "secret_[0-9a-zA-Z]{43}", "endpoints": [{"url": "https://api.notion.com/v1/users/me", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Linear", "regex": "lin_api_[0-9a-zA-Z]{40}", "endpoints": [{"url": "https://api.linear.app/graphql", "method": "POST", "header": "Authorization", "prefix": ""}]},
    {"name": "Airtable", "regex": "pat[0-9a-zA-Z]{15,30}\\.[0-9a-f]{64}", "endpoints": [{"url": "https://api.airtable.com/v0/meta/whoami", "method": "GET", "header": "Authorization", "prefix": "Bearer "}]},
    {"name": "Datadog", "regex": "[0-9a-f]{32}", "endpoints": [{"url": "https://api.datadoghq.com/api/v1/validate", "method": "GET", "header": "DD-API-KEY", "prefix": ""}]},
    {"name": "Mapbox", "regex": "pk\\.[0-9a-zA-Z\\-\\_]{60,100}", "endpoints": [{"url": "https://api.mapbox.com/geocoding/v5/mapbox.places/Los%20Angeles.json?access_token={KEY}", "method": "GET", "header": "", "prefix": ""}]}
  ]
}
`

// --- Updated Load Signatures Function ---
func loadSignatures() []Signature {
	var config Config
	
	// Seedha upar diye gaye constant string se JSON parse karein
	if err := json.Unmarshal([]byte(megaSignaturesJSON), &config); err == nil {
		return config.Platforms
	}
	
	// Extreme Fallback (agar upar wala JSON kharab ho jaye, jo ki nahi hoga)
	color.Yellow("[!] Failed to load embedded mega database. Using minimal fallback.")
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
