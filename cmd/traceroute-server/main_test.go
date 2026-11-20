// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadAuthToken(t *testing.T) {
	tests := []struct {
		name        string
		env         *string
		fileContent *string
		wantToken   string
		wantSource  string
		wantErr     string
	}{
		{name: "nothing set", wantToken: "", wantSource: authTokenEnv},
		{name: "env", env: ptr("env-token-placeholder\n"), wantToken: "env-token-placeholder", wantSource: authTokenEnv},
		{name: "env set but empty", env: ptr(" "), wantErr: "set but empty"},
		{name: "file", fileContent: ptr("file-token-placeholder\n"), wantToken: "file-token-placeholder", wantSource: "file"},
		{name: "empty file", fileContent: ptr("\n"), wantErr: "is empty"},
		{name: "both", env: ptr("env-token-placeholder"), fileContent: ptr("file-token-placeholder"), wantErr: "not both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != nil {
				t.Setenv(authTokenEnv, *tt.env)
			} else {
				t.Setenv(authTokenEnv, "")
				require.NoError(t, os.Unsetenv(authTokenEnv))
			}
			path := ""
			if tt.fileContent != nil {
				path = writeTokenFile(t, *tt.fileContent)
			}

			token, source, err := loadAuthToken(path)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
			if tt.wantSource == "file" {
				assert.Equal(t, path, source)
			} else {
				assert.Equal(t, tt.wantSource, source)
			}
		})
	}
}

func TestLoadAuthTokenMissingFile(t *testing.T) {
	t.Setenv(authTokenEnv, "")
	require.NoError(t, os.Unsetenv(authTokenEnv))

	_, _, err := loadAuthToken(filepath.Join(t.TempDir(), "missing"))

	assert.ErrorContains(t, err, "reading --auth-token-file")
}

func ptr(s string) *string { return &s }
