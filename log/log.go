package log

import "log"

var enabled = true

func SetVerbose(v bool) {
	enabled = v
}

var (
	Tracef = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[TRACE] "+format, args...)
		}
	}

	Trace = func(format string) {
		if enabled {
			log.Print("[TRACE] " + format)
		}
	}

	Infof = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[INFO] "+format, args...)
		}
	}

	Debugf = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[DEBUG] "+format, args...)
		}
	}

	Errorf = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[ERROR] "+format, args...)
		}
	}

	Warnf = func(format string, args ...interface{}) {
		if enabled {
			log.Printf("[WARN] "+format, args...)
		}
	}

	TraceFunc = func(logFunc func() string) {
		if enabled {
			log.Print("[TRACEFUNC] " + logFunc())
		}
	}
)
