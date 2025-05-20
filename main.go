package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"NoSQLi/banner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

// Constants for payload URLs
const (
	PayloadsBaseURL = "https://raw.githubusercontent.com/yourusername/nosqli-scanner/main/payloads"
	PayloadsDir     = "payloads"
)

// ScanOptions holds the configuration for the scanner
type ScanOptions struct {
	URL        string
	Method     string
	Headers    map[string]string
	Cookies    string
	Data       string
	Payloads   string
	DBType     string
	Enumerate  bool
	EnumType   string // "databases", "collections", "fields", "data"
	Collection string // Collection/table to enumerate
	Field      string // Field to enumerate
	Where      string // Custom conditions for data enumeration
	Limit      int    // Limit the number of results
}

// PayloadFile represents the structure of our payload JSON files
type PayloadFile struct {
	AuthBypass []map[string]interface{} `json:"auth_bypass"`
	Injection  []map[string]interface{} `json:"injection"`
	Enumerate  []map[string]interface{} `json:"enumerate"`
}

// EnumResult represents enumeration results
type EnumResult struct {
	Type     string      `json:"type"`
	Name     string      `json:"name"`
	Count    int         `json:"count,omitempty"`
	Fields   []string    `json:"fields,omitempty"`
	Data     [][]string  `json:"data,omitempty"`
	Metadata interface{} `json:"metadata,omitempty"`
}

// Scanner represents our NoSQL injection scanner
type Scanner struct {
	options    *ScanOptions
	client     *http.Client
	payloads   PayloadFile
	detectedDB string
	report     map[string]interface{}
}

// NewScanner creates a new scanner instance
func NewScanner(options *ScanOptions) *Scanner {
	return &Scanner{
		options: options,
		client: &http.Client{
			Timeout: time.Second * 10,
		},
		report: make(map[string]interface{}),
	}
}

// ensurePayloadsExist checks and downloads payload files if they don't exist
func (s *Scanner) ensurePayloadsExist() error {
	if err := os.MkdirAll(PayloadsDir, 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %v", err)
	}

	dbTypes := []string{"mongodb", "couchdb", "elasticsearch", "firebase"}
	for _, dbType := range dbTypes {
		filename := filepath.Join(PayloadsDir, dbType+".json")
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			color.Yellow("Downloading %s payloads...", dbType)
			if err := s.downloadPayloadFile(dbType); err != nil {
				return fmt.Errorf("failed to download %s payloads: %v", dbType, err)
			}
		}
	}
	return nil
}

// downloadPayloadFile downloads a specific payload file
func (s *Scanner) downloadPayloadFile(dbType string) error {
	url := fmt.Sprintf("%s/%s.json", PayloadsBaseURL, dbType)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	file, err := os.Create(filepath.Join(PayloadsDir, dbType+".json"))
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	return err
}

// detectDatabaseType attempts to identify the NoSQL database being used
func (s *Scanner) detectDatabaseType() string {
	if s.options.DBType != "" {
		return s.options.DBType
	}

	color.Blue("Attempting to detect database type...")
	
	// Make a baseline request
	req, _ := http.NewRequest(http.MethodGet, s.options.URL, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return "mongodb" // Default to MongoDB if detection fails
	}
	defer resp.Body.Close()

	// Check headers
	server := strings.ToLower(resp.Header.Get("Server"))
	switch {
	case strings.Contains(server, "couchdb"):
		return "couchdb"
	case strings.Contains(server, "mongodb"):
		return "mongodb"
	}

	// Read response body
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.ToLower(string(body))

	// Check response patterns
	switch {
	case strings.Contains(bodyStr, "mongoerror") || strings.Contains(bodyStr, "bson"):
		return "mongodb"
	case strings.Contains(bodyStr, "couchdb"):
		return "couchdb"
	case strings.Contains(bodyStr, "_shards") || strings.Contains(bodyStr, "elastic"):
		return "elasticsearch"
	case strings.Contains(bodyStr, "firebase"):
		return "firebase"
	}

	return "mongodb" // Default to MongoDB
}

// loadPayloads loads the payload file for the detected database
func (s *Scanner) loadPayloads() error {
	filename := filepath.Join(PayloadsDir, s.detectedDB+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read payload file: %v", err)
	}

	if err := json.Unmarshal(data, &s.payloads); err != nil {
		return fmt.Errorf("failed to parse payload file: %v", err)
	}

	return nil
}

// compareResponses compares two responses to detect vulnerabilities
func (s *Scanner) compareResponses(baseResp, testResp *http.Response) (bool, string) {
	// Status code change detection
	if baseResp.StatusCode != testResp.StatusCode {
		if (baseResp.StatusCode == http.StatusUnauthorized || baseResp.StatusCode == http.StatusForbidden) &&
			testResp.StatusCode == http.StatusOK {
			return true, "Authentication bypass detected"
		}
	}

	// Response size change detection
	baseBody, _ := io.ReadAll(baseResp.Body)
	testBody, _ := io.ReadAll(testResp.Body)
	
	if len(baseBody) > 0 {
		sizeDiff := float64(len(testBody)-len(baseBody)) / float64(len(baseBody))
		if sizeDiff > 0.5 { // 50% size difference threshold
			return true, "Significant response size change detected"
		}
	}

	// Error message detection
	testBodyStr := strings.ToLower(string(testBody))
	errorPatterns := []string{"error", "exception", "traceback", "mongoerror", "syntaxerror"}
	for _, pattern := range errorPatterns {
		if strings.Contains(testBodyStr, pattern) {
			return true, "Database error message exposed"
		}
	}

	return false, ""
}

// testPayload tests a single payload for vulnerability
func (s *Scanner) testPayload(payload map[string]interface{}, paramName string) (bool, string) {
	// Create baseline request
	baseReq, err := http.NewRequest(s.options.Method, s.options.URL, nil)
	if err != nil {
		return false, ""
	}

	// Add headers and cookies
	for k, v := range s.options.Headers {
		baseReq.Header.Set(k, v)
	}
	if s.options.Cookies != "" {
		baseReq.Header.Set("Cookie", s.options.Cookies)
	}

	// Perform baseline request
	baseResp, err := s.client.Do(baseReq)
	if err != nil {
		return false, ""
	}
	defer baseResp.Close()

	// Create injection request
	var injData string
	if s.options.Method == http.MethodPost {
		// Modify JSON data with payload
		var jsonData map[string]interface{}
		json.Unmarshal([]byte(s.options.Data), &jsonData)
		jsonData[paramName] = payload
		injDataBytes, _ := json.Marshal(jsonData)
		injData = string(injDataBytes)
	}

	injReq, _ := http.NewRequest(s.options.Method, s.options.URL, strings.NewReader(injData))
	for k, v := range s.options.Headers {
		injReq.Header.Set(k, v)
	}
	if s.options.Cookies != "" {
		injReq.Header.Set("Cookie", s.options.Cookies)
	}

	// Perform injection request
	injResp, err := s.client.Do(injReq)
	if err != nil {
		return false, ""
	}
	defer injResp.Close()

	return s.compareResponses(baseResp, injResp)
}

// testEnumPayload tests enumeration payloads
func (s *Scanner) testEnumPayload(payload map[string]interface{}, paramName string) (*EnumResult, error) {
	// Modify request data based on payload
	var injData string
	if s.options.Method == http.MethodPost {
		var jsonData map[string]interface{}
		json.Unmarshal([]byte(s.options.Data), &jsonData)
		jsonData[paramName] = payload
		injDataBytes, _ := json.Marshal(jsonData)
		injData = string(injDataBytes)
	}

	// Create request
	req, err := http.NewRequest(s.options.Method, s.options.URL, strings.NewReader(injData))
	if err != nil {
		return nil, err
	}

	// Add headers and cookies
	for k, v := range s.options.Headers {
		req.Header.Set(k, v)
	}
	if s.options.Cookies != "" {
		req.Header.Set("Cookie", s.options.Cookies)
	}

	// Make request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try to extract information from response
	result := &EnumResult{
		Type: s.options.EnumType,
	}

	// Parse response based on database type and enumeration type
	switch s.detectedDB {
	case "mongodb":
		return s.parseMongoDBResponse(body, result)
	case "couchdb":
		return s.parseCouchDBResponse(body, result)
	case "elasticsearch":
		return s.parseElasticsearchResponse(body, result)
	case "firebase":
		return s.parseFirebaseResponse(body, result)
	}

	return result, nil
}

// parseMongoDBResponse parses MongoDB enumeration response
func (s *Scanner) parseMongoDBResponse(body []byte, result *EnumResult) (*EnumResult, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return result, err
	}

	switch s.options.EnumType {
	case "databases":
		if databases, ok := data["databases"].([]interface{}); ok {
			for _, db := range databases {
				if dbName, ok := db.(map[string]interface{})["name"].(string); ok {
					result.Fields = append(result.Fields, dbName)
				}
			}
		}
	case "collections":
		if collections, ok := data["collections"].([]interface{}); ok {
			for _, col := range collections {
				if colName, ok := col.(string); ok {
					result.Fields = append(result.Fields, colName)
				}
			}
		}
	case "fields":
		if doc, ok := data["result"].(map[string]interface{}); ok {
			for field := range doc {
				result.Fields = append(result.Fields, field)
			}
		}
	case "data":
		if docs, ok := data["result"].([]interface{}); ok {
			for _, doc := range docs {
				if docMap, ok := doc.(map[string]interface{}); ok {
					var row []string
					for _, field := range result.Fields {
						if val, ok := docMap[field]; ok {
							row = append(row, fmt.Sprintf("%v", val))
						} else {
							row = append(row, "")
						}
					}
					result.Data = append(result.Data, row)
				}
			}
		}
	}

	return result, nil
}

// parseCouchDBResponse parses CouchDB enumeration response
func (s *Scanner) parseCouchDBResponse(body []byte, result *EnumResult) (*EnumResult, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return result, err
	}

	switch s.options.EnumType {
	case "databases":
		if databases, ok := data["databases"].([]interface{}); ok {
			for _, db := range databases {
				if dbName, ok := db.(string); ok {
					result.Fields = append(result.Fields, dbName)
				}
			}
		}
	case "collections":
		if docs, ok := data["rows"].([]interface{}); ok {
			for _, doc := range docs {
				if docMap, ok := doc.(map[string]interface{}); ok {
					if id, ok := docMap["id"].(string); ok {
						result.Fields = append(result.Fields, id)
					}
				}
			}
		}
	}

	return result, nil
}

// parseElasticsearchResponse parses Elasticsearch enumeration response
func (s *Scanner) parseElasticsearchResponse(body []byte, result *EnumResult) (*EnumResult, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return result, err
	}

	switch s.options.EnumType {
	case "databases":
		if indices, ok := data["indices"].(map[string]interface{}); ok {
			for index := range indices {
				result.Fields = append(result.Fields, index)
			}
		}
	case "fields":
		if mappings, ok := data["mappings"].(map[string]interface{}); ok {
			if properties, ok := mappings["properties"].(map[string]interface{}); ok {
				for field := range properties {
					result.Fields = append(result.Fields, field)
				}
			}
		}
	}

	return result, nil
}

// parseFirebaseResponse parses Firebase enumeration response
func (s *Scanner) parseFirebaseResponse(body []byte, result *EnumResult) (*EnumResult, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return result, err
	}

	// Extract fields from Firebase response
	if s.options.EnumType == "data" {
		var fields []string
		var extractFields func(map[string]interface{}, string)
		
		extractFields = func(obj map[string]interface{}, prefix string) {
			for k, v := range obj {
				field := k
				if prefix != "" {
					field = prefix + "." + k
				}
				if nested, ok := v.(map[string]interface{}); ok {
					extractFields(nested, field)
				} else {
					fields = append(fields, field)
				}
			}
		}

		if root, ok := data.(map[string]interface{}); ok {
			extractFields(root, "")
		}
		result.Fields = fields
	}

	return result, nil
}

// enumerateData performs the data enumeration scan
func (s *Scanner) enumerateData() ([]*EnumResult, error) {
	color.Blue("\n🔍 Starting database enumeration...")
	
	var results []*EnumResult

	// Load enumeration payloads
	if err := s.loadPayloads(); err != nil {
		return nil, err
	}

	// Get enumeration payloads based on database type
	payloads := s.payloads.Enumerate

	color.Yellow("\nExecuting enumeration queries...")
	
	for _, payload := range payloads {
		// Skip payloads not matching the requested enumeration type
		if payloadType, ok := payload["type"].(string); !ok || payloadType != s.options.EnumType {
			continue
		}

		// Customize payload based on user options
		if s.options.Collection != "" {
			payload["collection"] = s.options.Collection
		}
		if s.options.Field != "" {
			payload["field"] = s.options.Field
		}
		if s.options.Where != "" {
			if conditions := gjson.Get(s.options.Where, "@this"); conditions.Exists() {
				payload["conditions"] = conditions.Value()
			}
		}
		if s.options.Limit > 0 {
			payload["limit"] = s.options.Limit
		}

		result, err := s.testEnumPayload(payload, "query")
		if err != nil {
			color.Red("Error executing enumeration payload: %v", err)
			continue
		}

		if result != nil && len(result.Fields) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

// scan performs the full vulnerability and enumeration scan
func (s *Scanner) scan() error {
	// Ensure payloads exist
	if err := s.ensurePayloadsExist(); err != nil {
		return err
	}

	// Detect HTTP method if not specified
	if s.options.Method == "" {
		s.options.Method = s.detectMethod()
		color.Green("✓ Detected HTTP method: %s", s.options.Method)
	}

	// Detect database type
	s.detectedDB = s.detectDatabaseType()
	color.Green("✓ Detected database type: %s", s.detectedDB)

	// Load payloads
	if err := s.loadPayloads(); err != nil {
		return err
	}
	color.Green("✓ Loaded payloads for %s", s.detectedDB)

	// Start testing
	color.Blue("\nTesting for vulnerabilities...")
	
	var vulnerabilities []map[string]interface{}

	// Test AUTH BYPASS payloads
	for _, payload := range s.payloads.AuthBypass {
		color.Yellow("Testing auth bypass payload...")
		isVuln, reason := s.testPayload(payload, "username")
		if isVuln {
			vulnerabilities = append(vulnerabilities, map[string]interface{}{
				"type":    "Authentication Bypass",
				"payload": payload,
				"reason":  reason,
			})
		}
	}

	// Test INJECTION payloads
	for _, payload := range s.payloads.Injection {
		color.Yellow("Testing injection payload...")
		isVuln, reason := s.testPayload(payload, "query")
		if isVuln {
			vulnerabilities = append(vulnerabilities, map[string]interface{}{
				"type":    "Injection",
				"payload": payload,
				"reason":  reason,
			})
		}
	}

	// If enumeration was requested, perform it
	if s.options.Enumerate {
		results, err := s.enumerateData()
		if err != nil {
			return fmt.Errorf("enumeration failed: %v", err)
		}

		// Print enumeration results
		color.Blue("\n📊 Enumeration Results:")
		for _, result := range results {
			switch result.Type {
			case "databases":
				color.Green("\nFound databases:")
				for _, db := range result.Fields {
					fmt.Printf("- %s\n", db)
				}

			case "collections":
				color.Green("\nFound collections/tables:")
				for _, col := range result.Fields {
					fmt.Printf("- %s\n", col)
				}

			case "fields":
				color.Green("\nFound fields/columns:")
				for _, field := range result.Fields {
					fmt.Printf("- %s\n", field)
				}

			case "data":
				if len(result.Data) > 0 {
					color.Green("\nExtracted data:")
					// Print header
					fmt.Println(strings.Join(result.Fields, " | "))
					fmt.Println(strings.Repeat("-", len(strings.Join(result.Fields, " | "))))
					// Print data rows
					for _, row := range result.Data {
						fmt.Println(strings.Join(row, " | "))
					}
				}
			}
		}

		// Add enumeration results to the report
		s.report["enumeration"] = results
	}

	// Generate report
	report := map[string]interface{}{
		"scan_info": map[string]interface{}{
			"url":          s.options.URL,
			"method":       s.options.Method,
			"detected_db":  s.detectedDB,
			"timestamp":    time.Now().Format(time.RFC3339),
			"total_tests":  len(s.payloads.AuthBypass) + len(s.payloads.Injection),
			"total_vulns": len(vulnerabilities),
		},
		"vulnerabilities": vulnerabilities,
	}

	// Save report
	reportFile := fmt.Sprintf("nosql_scan_%d.json", time.Now().Unix())
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(reportFile, reportJSON, 0644); err != nil {
		return fmt.Errorf("failed to save report: %v", err)
	}

	// Print summary
	color.Blue("\n📊 Scan Summary:")
	color.White("URL: %s", s.options.URL)
	color.White("Database: %s", s.detectedDB)
	color.White("Total tests: %d", len(s.payloads.AuthBypass)+len(s.payloads.Injection))
	if len(vulnerabilities) > 0 {
		color.Red("Vulnerabilities found: %d", len(vulnerabilities))
	} else {
		color.Green("No vulnerabilities found")
	}
	color.White("Report saved to: %s", reportFile)

	return nil
}

func main() {
	var opts ScanOptions
	var headersStr string	// Show the banner
	banner.ShowBanner()

	rootCmd := &cobra.Command{
		Use:   "NoSQLi",
		Short: "A NoSQL injection vulnerability scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse headers
			if headersStr != "" {
				if err := json.Unmarshal([]byte(headersStr), &opts.Headers); err != nil {
					return fmt.Errorf("invalid headers format: %v", err)
				}
			}

			scanner := NewScanner(&opts)
			return scanner.scan()
		},
	}	rootCmd.Flags().StringVarP(&opts.URL, "url", "u", "", "Target URL")
	rootCmd.Flags().StringVarP(&opts.Method, "method", "m", "", "HTTP method (auto-detected if not specified)")
	rootCmd.Flags().StringVarP(&headersStr, "headers", "H", "", "Headers as JSON string")
	rootCmd.Flags().StringVarP(&opts.Cookies, "cookies", "c", "", "Cookie string")
	rootCmd.Flags().StringVarP(&opts.Data, "data", "d", "", "POST data as JSON string")
	rootCmd.Flags().StringVarP(&opts.DBType, "db-type", "t", "", "Force database type (mongodb, couchdb, elasticsearch, firebase)")
	
	// Database enumeration flags
	rootCmd.Flags().BoolVarP(&opts.Enumerate, "enum", "e", false, "Enable database enumeration")
	rootCmd.Flags().StringVar(&opts.EnumType, "enum-type", "", "Type of enumeration (databases, collections, fields, data)")
	rootCmd.Flags().StringVar(&opts.Collection, "collection", "", "Collection/table to enumerate")
	rootCmd.Flags().StringVar(&opts.Field, "field", "", "Field/column to enumerate")
	rootCmd.Flags().StringVar(&opts.Where, "where", "", "Conditions for data enumeration (JSON format)")
	rootCmd.Flags().IntVar(&opts.Limit, "limit", 0, "Limit the number of results")
	rootCmd.Flags().BoolVarP(&opts.Enumerate, "enumerate", "e", false, "Enable database enumeration")
	rootCmd.Flags().StringVarP(&opts.EnumType, "enum-type", "T", "", "Enumeration type (databases, collections, fields, data)")
	rootCmd.Flags().StringVarP(&opts.Collection, "collection", "C", "", "Collection/table to enumerate")
	rootCmd.Flags().StringVarP(&opts.Field, "field", "f", "", "Field to enumerate")
	rootCmd.Flags().StringVarP(&opts.Where, "where", "w", "", "Custom conditions for data enumeration")
	rootCmd.Flags().IntVarP(&opts.Limit, "limit", "l", 0, "Limit the number of results")

	rootCmd.MarkFlagRequired("url")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
