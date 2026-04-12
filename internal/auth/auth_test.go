package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr string
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: "no authorization header included",
		},
		{
			name:    "malformed header missing scheme",
			headers: http.Header{"Authorization": []string{"Bearer some-key"}},
			wantErr: "malformed authorization header",
		},
		{
			name:    "malformed header single value",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: "malformed authorization header",
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("expected error %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, got)
			}
		})
	}
}
