// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package log

import (
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLevel LogLevel
		wantErr   bool
	}{
		{
			name:      "error level",
			input:     "error",
			wantLevel: LevelError,
			wantErr:   false,
		},
		{
			name:      "warn level",
			input:     "warn",
			wantLevel: LevelWarn,
			wantErr:   false,
		},
		{
			name:      "info level",
			input:     "info",
			wantLevel: LevelInfo,
			wantErr:   false,
		},
		{
			name:      "debug level",
			input:     "debug",
			wantLevel: LevelDebug,
			wantErr:   false,
		},
		{
			name:      "trace level",
			input:     "trace",
			wantLevel: LevelTrace,
			wantErr:   false,
		},
		{
			name:      "invalid level - uppercase",
			input:     "INFO",
			wantLevel: 0,
			wantErr:   true,
		},
		{
			name:      "invalid level - random string",
			input:     "invalid",
			wantLevel: 0,
			wantErr:   true,
		},
		{
			name:      "invalid level - empty string",
			input:     "",
			wantLevel: 0,
			wantErr:   true,
		},
		{
			name:      "invalid level - number",
			input:     "123",
			wantLevel: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevel, err := ParseLogLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLogLevel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotLevel != tt.wantLevel {
				t.Errorf("ParseLogLevel() = %v, want %v", gotLevel, tt.wantLevel)
			}
			if tt.wantErr && err == nil {
				t.Error("ParseLogLevel() expected error but got nil")
			}
		})
	}
}

func TestLogLevelOrder(t *testing.T) {
	// Test that log levels are in ascending order
	if !(LevelError < LevelWarn && LevelWarn < LevelInfo && LevelInfo < LevelDebug && LevelDebug < LevelTrace) {
		t.Error("Log levels are not in expected ascending order")
	}
}
