package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey some-secret-key"},
			},
			expectedKey:   "some-secret-key",
			expectedError: "",
		},
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "Malformed header (missing key)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Wrong prefix (Bearer instead of ApiKey)",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if the error matches expectation
			if err != nil && err.Error() != tt.expectedError {
				t.Errorf("expected error: %v, got: %v", tt.expectedError, err)
			}
			if err == nil && tt.expectedError != "" {
				t.Errorf("expected error: %v, got: nil", tt.expectedError)
			}

			// Check if the key matches expectation
			if key != tt.expectedKey {
				t.Errorf("expected key: %v, got: %v", tt.expectedKey, key)
			}
		})
	}
}
