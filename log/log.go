// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package log

import (
	"fmt"
	"log"
)

// LogLevel represents the logging level
type LogLevel int

const (
	// LevelError only shows errors
	LevelError LogLevel = iota
	// LevelWarn shows warnings and errors
	LevelWarn
	// LevelInfo shows info, warnings, and errors
	LevelInfo
	// LevelDebug shows debug, info, warnings, and errors
	LevelDebug
	// LevelTrace shows all log messages
	LevelTrace
)

var (
	enabled  = true
	logLevel = LevelInfo
)

// EnabledLogging enables or disables logging (for backward compatibility)
func EnabledLogging(v bool) {
	enabled = v
}

// SetLogLevel sets the logging level
func SetLogLevel(level LogLevel) {
	logLevel = level
	enabled = true
}

var logLevelMap = map[string]LogLevel{
	"error": LevelError,
	"warn":  LevelWarn,
	"info":  LevelInfo,
	"debug": LevelDebug,
	"trace": LevelTrace,
}

// ParseLogLevel converts a string to a LogLevel
func ParseLogLevel(s string) (LogLevel, error) {
	if level, ok := logLevelMap[s]; ok {
		return level, nil
	}
	return 0, fmt.Errorf("invalid log level: %q (valid levels: error, warn, info, debug, trace)", s)
}

type Logger struct {
	Tracef    func(format string, args ...interface{})
	Trace     func(format string)
	Infof     func(format string, args ...interface{})
	Debugf    func(format string, args ...interface{})
	Warnf     func(format string, args ...interface{}) error
	Errorf    func(format string, args ...interface{}) error
	TraceFunc func(func() string)
}

var logger = Logger{
	Tracef:    defaultTracef,
	Trace:     defaultTrace,
	Infof:     defaultInfof,
	Debugf:    defaultDebugf,
	Warnf:     defaultWarnf,
	Errorf:    defaultErrorf,
	TraceFunc: defaultTraceFunc,
}

func SetLogger(l Logger) {
	logger = l
}

func Tracef(format string, args ...interface{}) {
	if logger.Tracef != nil {
		logger.Tracef(format, args...)
	}
}

func Trace(format string, args ...interface{}) {
	if logger.Trace != nil {
		logger.Trace(format)
	}
}

func Infof(format string, args ...interface{}) {
	if logger.Infof != nil {
		logger.Infof(format, args...)
	}
}

func Debugf(format string, args ...interface{}) {
	if logger.Debugf != nil {
		logger.Debugf(format, args...)
	}
}

func Warnf(format string, args ...interface{}) error {
	if logger.Warnf != nil {
		return logger.Warnf(format, args...)
	}
	return nil
}

func Errorf(format string, args ...interface{}) error {
	if logger.Errorf != nil {
		return logger.Errorf(format, args...)
	}
	return nil
}

func TraceFunc(logFunc func() string) {
	if logger.TraceFunc != nil {
		logger.TraceFunc(logFunc)
	}
}

var (
	defaultTracef = func(format string, args ...interface{}) {
		if enabled && logLevel >= LevelTrace {
			log.Printf("[TRACE] "+format, args...)
		}
	}

	defaultTrace = func(format string) {
		if enabled && logLevel >= LevelTrace {
			log.Print("[TRACE] " + format)
		}
	}

	defaultInfof = func(format string, args ...interface{}) {
		if enabled && logLevel >= LevelInfo {
			log.Printf("[INFO] "+format, args...)
		}
	}

	defaultDebugf = func(format string, args ...interface{}) {
		if enabled && logLevel >= LevelDebug {
			log.Printf("[DEBUG] "+format, args...)
		}
	}

	defaultErrorf = func(format string, args ...interface{}) error {
		if enabled && logLevel >= LevelError {
			log.Printf("[ERROR] "+format, args...)
		}
		return nil
	}

	defaultWarnf = func(format string, args ...interface{}) error {
		if enabled && logLevel >= LevelWarn {
			log.Printf("[WARN] "+format, args...)
		}
		return nil
	}

	defaultTraceFunc = func(logFunc func() string) {
		if enabled && logLevel >= LevelTrace {
			log.Print("[TRACEFUNC] " + logFunc())
		}
	}
)
