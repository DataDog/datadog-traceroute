// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package log

import "log"

var enabled = true

func SetVerbose(v bool) {
	enabled = v
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
		if enabled {
			log.Printf("[TRACE] "+format, args...)
		}
	}

	defaultTrace = func(format string) {
		if enabled {
			log.Print("[TRACE] " + format)
		}
	}

	defaultInfof = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[INFO] "+format, args...)
		}
	}

	defaultDebugf = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[DEBUG] "+format, args...)
		}
	}

	defaultErrorf = func(format string, args ...interface{}) error {
		if enabled {
			log.Printf("[ERROR] "+format, args...)
		}
		return nil
	}

	defaultWarnf = func(format string, args ...interface{}) error {
		if enabled {
			log.Printf("[WARN] "+format, args...)
		}
		return nil
	}

	defaultTraceFunc = func(logFunc func() string) {
		if enabled {
			log.Print("[TRACEFUNC] " + logFunc())
		}
	}
)
