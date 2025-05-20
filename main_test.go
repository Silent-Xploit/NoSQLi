package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectDatabaseType(t *testing.T) {
	tests := []struct {
		name           string
		serverHeader   string
		responseBody   string
		expectedDBType string
	}{
		{
			name:           "MongoDB Detection via Header",
			serverHeader:   "MongoDB/4.4",
			responseBody:   "",
			expectedDBType: "mongodb",
		},
		{
			name:           "CouchDB Detection via Header",
			serverHeader:   "CouchDB/3.1.0",
			responseBody:   "",
			expectedDBType: "couchdb",
		},
		{
			name:           "MongoDB Detection via Error",
			serverHeader:   "",
			responseBody:   `{"error": "MongoError: Invalid query"}`,
			expectedDBType: "mongodb",
		},
		{
			name:           "Elasticsearch Detection via Response",
			serverHeader:   "",
			responseBody:   `{"_shards": {"total": 5}}`,
			expectedDBType: "elasticsearch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.serverHeader != "" {
					w.Header().Set("Server", tt.serverHeader)
				}
				w.Write([]byte(tt.responseBody))
			}))
			defer ts.Close()

			// Create scanner with test options
			scanner := NewScanner(&ScanOptions{
				URL:    ts.URL,
				Method: "GET",
			})

			detectedDB := scanner.detectDatabaseType()
			if detectedDB != tt.expectedDBType {
				t.Errorf("Expected database type %s, got %s", tt.expectedDBType, detectedDB)
			}
		})
	}
}

func TestCompareResponses(t *testing.T) {
	tests := []struct {
		name           string
		baseStatus     int
		baseBody      string
		testStatus    int
		testBody      string
		expectVuln    bool
		expectedReason string
	}{
		{
			name:           "Auth Bypass Detection",
			baseStatus:     401,
			baseBody:       "Unauthorized",
			testStatus:     200,
			testBody:       "Welcome admin",
			expectVuln:     true,
			expectedReason: "Authentication bypass detected",
		},
		{
			name:           "Error Message Exposure",
			baseStatus:     200,
			baseBody:       "[]",
			testStatus:     500,
			testBody:       "MongoError: Invalid operator",
			expectVuln:     true,
			expectedReason: "Database error message exposed",
		},
		{
			name:           "No Vulnerability",
			baseStatus:     200,
			baseBody:       "[]",
			testStatus:     200,
			testBody:       "[]",
			expectVuln:     false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(&ScanOptions{
				URL:    "http://test.com",
				Method: "GET",
			})

			baseResp := &http.Response{
				StatusCode: tt.baseStatus,
				Body:      &dummyBody{[]byte(tt.baseBody)},
			}

			testResp := &http.Response{
				StatusCode: tt.testStatus,
				Body:      &dummyBody{[]byte(tt.testBody)},
			}

			isVuln, reason := scanner.compareResponses(baseResp, testResp)
			if isVuln != tt.expectVuln {
				t.Errorf("Expected vulnerability detection %v, got %v", tt.expectVuln, isVuln)
			}
			if isVuln && reason != tt.expectedReason {
				t.Errorf("Expected reason %s, got %s", tt.expectedReason, reason)
			}
		})
	}
}

// dummyBody implements io.ReadCloser for testing
type dummyBody struct {
	content []byte
}

func (d *dummyBody) Read(p []byte) (n int, err error) {
	copy(p, d.content)
	return len(d.content), nil
}

func (d *dummyBody) Close() error {
	return nil
}
