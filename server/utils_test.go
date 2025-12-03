// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import "testing"

func TestHelperFunctions(t *testing.T) {
	t.Run("getStringParam", func(t *testing.T) {
		query := map[string][]string{
			"key1": {"value1"},
		}
		if got := getStringParam(query, "key1", "default"); got != "value1" {
			t.Errorf("expected 'value1', got '%s'", got)
		}
		if got := getStringParam(query, "missing", "default"); got != "default" {
			t.Errorf("expected 'default', got '%s'", got)
		}
	})

	t.Run("getIntParam", func(t *testing.T) {
		query := map[string][]string{
			"num": {"42"},
			"bad": {"not-a-number"},
		}
		if got := getIntParam(query, "num", 10); got != 42 {
			t.Errorf("expected 42, got %d", got)
		}
		if got := getIntParam(query, "missing", 10); got != 10 {
			t.Errorf("expected 10, got %d", got)
		}
		if got := getIntParam(query, "bad", 10); got != 10 {
			t.Errorf("expected 10 (default), got %d", got)
		}
	})

	t.Run("getBoolParam", func(t *testing.T) {
		query := map[string][]string{
			"true":  {"true"},
			"false": {"false"},
			"bad":   {"not-a-bool"},
		}
		if got := getBoolParam(query, "true", false); !got {
			t.Error("expected true")
		}
		if got := getBoolParam(query, "false", true); got {
			t.Error("expected false")
		}
		if got := getBoolParam(query, "missing", true); !got {
			t.Error("expected true (default)")
		}
		if got := getBoolParam(query, "bad", true); !got {
			t.Error("expected true (default)")
		}
	})
}
