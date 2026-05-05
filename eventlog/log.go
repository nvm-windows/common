package eventlog

import (
	"fmt"

	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	// eventLogSupportsTypes is the set of event types the source will handle.
	eventLogSupportsTypes = eventlog.Error | eventlog.Warning | eventlog.Info

	// Default event IDs for a registered/named source.
	// InstallAsEventCreate (EventCreate.exe message table) supports IDs 1–1000.
	RegisteredInfoID    uint32 = 100
	RegisteredWarningID uint32 = 200
	RegisteredErrorID   uint32 = 300

	// Default event IDs when falling back to the generic Application log.
	// Not bound by the EventCreate 1–1000 constraint.
	FallbackInfoID    uint32 = 1000
	FallbackWarningID uint32 = 1001
	FallbackErrorID   uint32 = 1002
)

// sourceName is the Windows Event Log source name populated at build time.
// Falls back to "NVM for Windows" so the app is always functional.
var sourceName = "NVM for Windows"

// RegisterEventSource registers the application as a Windows Event Log source
// under HKLM. Requires elevation — called by the installer via --register-eventlog.
func RegisterEventSource(appName string) error {
	src := sourceName
	if appName != "" {
		src = appName
	}
	return eventlog.InstallAsEventCreate(src, eventLogSupportsTypes)
}

// UnregisterEventSource removes the application's Windows Event Log source
// registration from HKLM. Requires elevation — called by the uninstaller via
// --unregister-eventlog.
func UnregisterEventSource(appName string) error {
	src := sourceName
	if appName != "" {
		src = appName
	}
	return eventlog.Remove(src)
}

type EventLogger struct {
	log        *eventlog.Log
	source     string
	registered bool // true when using the named/registered source; false when using the Application fallback
}

func NewEventLogger(appName ...string) (*EventLogger, error) {
	src := sourceName
	if len(appName) > 0 && appName[0] != "" {
		src = appName[0]
	}

	// Prefer the registered custom source so events appear under the app name
	// in Event Viewer with proper descriptions.
	registered := true
	l, err := eventlog.Open(src)
	if err != nil {
		// Source not registered (installer ran without elevation, or first run
		// before registration). Fall back to the built-in Application log.
		src = "Application"
		registered = false
		l, err = eventlog.Open(src)
		if err != nil {
			return nil, err
		}
	}

	return &EventLogger{log: l, source: src, registered: registered}, nil
}

func (ev *EventLogger) Log(message string, code ...int) {
	eid := RegisteredInfoID
	if !ev.registered {
		eid = FallbackInfoID
	}
	if len(code) > 0 && code[0] > 0 {
		eid = uint32(code[0])
	}
	_ = ev.log.Info(eid, message)
}

func (ev *EventLogger) Logf(format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	code := args[len(args)-1]
	if _, ok := code.(int); ok {
		args = args[:len(args)-1]
		ev.Log(fmt.Sprintf(format, args...), code.(int))
	} else {
		ev.Log(fmt.Sprintf(format, args...))
	}
}

func (ev *EventLogger) Warn(message string, code ...int) {
	eid := RegisteredWarningID
	if !ev.registered {
		eid = FallbackWarningID
	}
	if len(code) > 0 && code[0] > 0 {
		eid = uint32(code[0])
	}
	_ = ev.log.Warning(eid, message)
}

func (ev *EventLogger) Warnf(format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	code := args[len(args)-1]
	if _, ok := code.(int); ok {
		args = args[:len(args)-1]
		ev.Warn(fmt.Sprintf(format, args...), code.(int))
	} else {
		ev.Warn(fmt.Sprintf(format, args...))
	}
}

func (ev *EventLogger) Error(err error, code ...int) {
	eid := RegisteredErrorID
	if !ev.registered {
		eid = FallbackErrorID
	}
	if len(code) > 0 && code[0] > 0 {
		eid = uint32(code[0])
	}
	_ = ev.log.Error(eid, err.Error())
}

func (ev *EventLogger) Errorf(format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	code := args[len(args)-1]
	if _, ok := code.(int); ok {
		args = args[:len(args)-1]
		ev.Error(fmt.Errorf(format, args...), code.(int))
	} else {
		ev.Error(fmt.Errorf(format, args...))
	}
}

// defaultLogger is the package-level logger used by the exported Log/Warn/Error
// convenience functions. nil if the Event Log is unavailable at startup.
var defaultLogger, _ = NewEventLogger()

func Log(message string, code ...int) {
	if defaultLogger != nil {
		defaultLogger.Log(message, code...)
	}
}

func Logf(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Logf(format, args...)
	}
}

func Warn(message string, code ...int) {
	if defaultLogger != nil {
		defaultLogger.Warn(message, code...)
	}
}

func Warnf(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Warnf(format, args...)
	}
}

func Error(err error, code ...int) {
	if defaultLogger != nil {
		defaultLogger.Error(err, code...)
	}
}

func Errorf(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Errorf(format, args...)
	}
}
