// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import "strconv"

// Helper functions for parsing query parameters

func getStringParam(query map[string][]string, key string, defaultValue string) string {
	if values, ok := query[key]; ok && len(values) > 0 {
		return values[0]
	}
	return defaultValue
}

func getIntParam(query map[string][]string, key string, defaultValue int) int {
	if values, ok := query[key]; ok && len(values) > 0 {
		if val, err := strconv.Atoi(values[0]); err == nil {
			return val
		}
	}
	return defaultValue
}

func getBoolParam(query map[string][]string, key string, defaultValue bool) bool {
	if values, ok := query[key]; ok && len(values) > 0 {
		if val, err := strconv.ParseBool(values[0]); err == nil {
			return val
		}
	}
	return defaultValue
}
