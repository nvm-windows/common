package eventlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	procEventRegister = advapi32.NewProc("EventRegister")
	procEventWrite    = advapi32.NewProc("EventWrite")

	sharedProvider  providerState
	defaultLoggerMu sync.Mutex

	// sourceName is the human-readable application name populated at build time.
	// The ETW provider identity itself is stable and does not vary by build.
	sourceName = providerDisplayName
)

type providerState struct {
	once   sync.Once
	handle uint64
	err    error
}

type EventLogger struct {
	source string
}

const (
	eventLogRegistryBase = `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT`
	providerGUIDValue    = `{4c0f8d8e-2d6b-4f93-9f0f-3f0d7b4e2d11}`
	classicEventLogBase  = `SYSTEM\CurrentControlSet\Services\EventLog`
)

// RegisterEventSource installs the machine-scoped provider manifest used by
// the certified ETW operational channel. Requires elevation.
func RegisterEventSource(appName string) error {
	_ = appName

	manifestPath, err := providerManifestPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(manifestPath); err != nil {
		return fmt.Errorf("event provider manifest not found at %s: %w", manifestPath, err)
	}

	resourcePath := providerResourceDllPath(manifestPath)
	if _, err := os.Stat(resourcePath); err != nil {
		return fmt.Errorf("event provider resource DLL not found at %s: %w", resourcePath, err)
	}

	_ = runWevtutil("um", manifestPath)
	removeRegistryTree(registry.LOCAL_MACHINE, eventLogRegistryBase+`\Publishers\`+providerGUIDValue)
	removeRegistryTree(registry.LOCAL_MACHINE, eventLogRegistryBase+`\Channels\`+operationalChannelPath())
	removeRegistryTree(registry.LOCAL_MACHINE, eventLogRegistryBase+`\Channels\`+adminChannelPath())
	removeLegacyClassicSource(providerName)

	if err := runWevtutil(
		"im", manifestPath,
		"/rf:"+resourcePath,
		"/mf:"+resourcePath,
		"/pf:"+resourcePath,
	); err != nil {
		return fmt.Errorf("failed to install event provider manifest: %w", err)
	}

	if err := runWevtutil("sl", operationalChannelPath(), "/e:true"); err != nil {
		// Non-fatal: channel enable can fail if Event Log service is restarting.
		_ = err
	}

	return nil
}

// UnregisterEventSource removes the machine-scoped provider manifest used by
// the certified ETW operational channel. Requires elevation.
func UnregisterEventSource(appName string) error {
	_ = appName

	manifestPath, err := providerManifestPath()
	if err != nil {
		return err
	}

	if err := runWevtutil("um", manifestPath); err != nil {
		return fmt.Errorf("failed to remove event provider manifest: %w", err)
	}
	removeLegacyClassicSource(providerName)

	return nil
}

func removeLegacyClassicSource(source string) {
	name := strings.TrimSpace(source)
	if name == "" {
		return
	}

	for _, logName := range []string{"Application", "System", "Security"} {
		removeRegistryTree(registry.LOCAL_MACHINE, classicEventLogBase+`\`+logName+`\`+name)
	}
}

func NewEventLogger(appName ...string) (*EventLogger, error) {
	src := sourceName
	if len(appName) > 0 && strings.TrimSpace(appName[0]) != "" {
		src = appName[0]
	}

	if _, err := providerHandle(); err != nil {
		return nil, err
	}

	return &EventLogger{source: src}, nil
}

func (ev *EventLogger) Log(message string, code ...int) {
	ev.writeOperational(operationalInfoDescriptor, message, parseCode(code))
}

func (ev *EventLogger) Logf(format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	code, formatArgs := splitFormatCode(args)
	ev.Log(fmt.Sprintf(format, formatArgs...), code)
}

func (ev *EventLogger) Warn(message string, code ...int) {
	ev.writeOperational(operationalWarningDescriptor, message, parseCode(code))
}

func (ev *EventLogger) Warnf(format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	code, formatArgs := splitFormatCode(args)
	ev.Warn(fmt.Sprintf(format, formatArgs...), code)
}

func (ev *EventLogger) Error(err error, code ...int) {
	if err == nil {
		return
	}

	ev.writeOperational(operationalErrorDescriptor, err.Error(), parseCode(code))
}

func (ev *EventLogger) Errorf(format string, args ...interface{}) {
	if len(args) == 0 {
		return
	}

	code, formatArgs := splitFormatCode(args)
	ev.Error(fmt.Errorf(format, formatArgs...), code)
}

func (ev *EventLogger) LogStructured(eventName string, payload any, code ...int) {
	ev.writeStructured(structuredInfoDescriptor, eventName, payload, parseCode(code))
}

func (ev *EventLogger) WarnStructured(eventName string, payload any, code ...int) {
	ev.writeStructured(structuredWarningDescriptor, eventName, payload, parseCode(code))
}

func (ev *EventLogger) ErrorStructured(eventName string, payload any, code ...int) {
	ev.writeStructured(structuredErrorDescriptor, eventName, payload, parseCode(code))
}

func (ev *EventLogger) writeOperational(descriptor eventDescriptor, message string, code int) {
	handle, err := providerHandle()
	if err != nil {
		return
	}

	sourceField, err := syscall.UTF16FromString(ev.source)
	if err != nil {
		return
	}
	messageField, err := syscall.UTF16FromString(message)
	if err != nil {
		return
	}
	codeField := uint32(code)

	fields := [3]eventDataDescriptor{
		utf16FieldDescriptor(sourceField),
		utf16FieldDescriptor(messageField),
		scalarFieldDescriptor(&codeField),
	}

	writeEvent(handle, descriptor, fields[:])
}

func (ev *EventLogger) writeStructured(descriptor eventDescriptor, eventName string, payload any, code int) {
	handle, err := providerHandle()
	if err != nil {
		return
	}

	eventName = strings.TrimSpace(eventName)
	if eventName == "" {
		return
	}

	payloadJSON, err := marshalStructuredPayload(payload)
	if err != nil {
		return
	}

	sourceField, err := syscall.UTF16FromString(ev.source)
	if err != nil {
		return
	}
	eventNameField, err := syscall.UTF16FromString(eventName)
	if err != nil {
		return
	}
	payloadField, err := syscall.UTF16FromString(payloadJSON)
	if err != nil {
		return
	}
	codeField := uint32(code)

	fields := [4]eventDataDescriptor{
		utf16FieldDescriptor(sourceField),
		utf16FieldDescriptor(eventNameField),
		utf16FieldDescriptor(payloadField),
		scalarFieldDescriptor(&codeField),
	}

	writeEvent(handle, descriptor, fields[:])
}

func writeEvent(handle uint64, descriptor eventDescriptor, fields []eventDataDescriptor) {
	status, _, _ := procEventWrite.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&descriptor)),
		uintptr(len(fields)),
		uintptr(unsafe.Pointer(&fields[0])),
	)
	if status != 0 {
		logRuntimeDiagnostic(fmt.Sprintf("EventWrite failed (status=%d event_id=%d channel=%d)", status, descriptor.ID, descriptor.Channel))
	} else {
		logRuntimeDiagnostic(fmt.Sprintf("EventWrite OK (event_id=%d channel=%d)", descriptor.ID, descriptor.Channel))
	}
}

func providerHandle() (uint64, error) {
	sharedProvider.once.Do(func() {
		var handle uint64
		status, _, _ := procEventRegister.Call(
			uintptr(unsafe.Pointer(&providerGUID)),
			0,
			0,
			uintptr(unsafe.Pointer(&handle)),
		)
		if status != 0 {
			sharedProvider.err = syscall.Errno(status)
			logRuntimeDiagnostic(fmt.Sprintf("EventRegister failed (status=%d)", status))
			return
		}

		sharedProvider.handle = handle
	})

	return sharedProvider.handle, sharedProvider.err
}

func providerResourceDllPath(manifestPath string) string {
	base := strings.TrimSuffix(manifestPath, filepath.Ext(manifestPath))
	return base + ".dll"
}

func providerManifestPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}

	exeDir := filepath.Dir(exePath)
	for _, candidate := range []string{
		filepath.Join(exeDir, providerManifestFileName),
		filepath.Join(filepath.Dir(exeDir), providerManifestFileName),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return filepath.Join(exeDir, providerManifestFileName), nil
}

func runWevtutil(args ...string) error {
	cmd := exec.Command("wevtutil.exe", args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return err
	}

	return fmt.Errorf("%w: %s", err, trimmed)
}

func logRuntimeDiagnostic(message string) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().UTC().Format(time.RFC3339Nano), message)
	for _, target := range []string{
		filepath.Join(os.Getenv("ProgramData"), "Author Software", "nvm", "logs", "eventlog-runtime.log"),
		filepath.Join(os.TempDir(), "nvm-eventlog-runtime.log"),
	} {
		if strings.TrimSpace(target) == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			continue
		}
		f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		f.WriteString(line)
		f.Close()
		return
	}
}

func operationalChannelPath() string {
	return providerDisplayName + "/Operational"
}

func adminChannelPath() string {
	return providerDisplayName + "/Admin"
}

func ensureRegistryPublisherConfiguration(manifestPath string) error {
	publisherPath := eventLogRegistryBase + `\Publishers\` + providerGUIDValue
	publisherKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, publisherPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to open publisher registry key: %w", err)
	}
	defer publisherKey.Close()

	if err := publisherKey.SetStringValue("", providerName); err != nil {
		return fmt.Errorf("failed to set publisher default value: %w", err)
	}
	_ = manifestPath
	for _, valueName := range []string{"MessageFileName", "ResourceFileName", "ParameterFileName"} {
		if err := publisherKey.DeleteValue(valueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("failed to clear publisher %s: %w", valueName, err)
		}
	}

	if err := setChannelReference(publisherPath, 0, operationalChannelPath(), providerOperationalChannel); err != nil {
		return err
	}
	if err := setChannelReference(publisherPath, 1, adminChannelPath(), providerOperationalChannel+1); err != nil {
		return err
	}

	return nil
}

func clearPublisherFilePathValues() error {
	publisherPath := eventLogRegistryBase + `\Publishers\` + providerGUIDValue
	publisherKey, err := registry.OpenKey(registry.LOCAL_MACHINE, publisherPath, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to open publisher key for file path cleanup: %w", err)
	}
	defer publisherKey.Close()

	for _, valueName := range []string{"MessageFileName", "ResourceFileName", "ParameterFileName"} {
		if err := publisherKey.DeleteValue(valueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("failed to clear publisher %s: %w", valueName, err)
		}
	}

	return nil
}

func setChannelReference(publisherPath string, index int, channelName string, channelID uint8) error {
	refPath := fmt.Sprintf(`%s\ChannelReferences\%d`, publisherPath, index)
	refKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, refPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to open publisher channel reference %d: %w", index, err)
	}
	defer refKey.Close()

	if err := refKey.SetStringValue("", channelName); err != nil {
		return fmt.Errorf("failed to set channel reference name: %w", err)
	}
	if err := refKey.SetDWordValue("Id", uint32(channelID)); err != nil {
		return fmt.Errorf("failed to set channel reference id: %w", err)
	}
	if err := refKey.SetDWordValue("Flags", 0); err != nil {
		return fmt.Errorf("failed to set channel reference flags: %w", err)
	}

	return nil
}

func ensureRegistryChannelConfiguration(channelPath string) error {
	fullPath := eventLogRegistryBase + `\Channels\` + channelPath
	channelKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, fullPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to open channel registry key: %w", err)
	}
	defer channelKey.Close()

	if err := channelKey.SetDWordValue("Enabled", 1); err != nil {
		return fmt.Errorf("failed to set channel Enabled: %w", err)
	}
	// EVT_CHANNEL_ISOLATION_TYPE: 0=Application, 1=System, 2=Custom.
	// System isolation blocks user-mode EventWrite calls; must use Application (0).
	if err := channelKey.SetDWordValue("Isolation", 0); err != nil {
		return fmt.Errorf("failed to set channel Isolation: %w", err)
	}
	if err := channelKey.SetDWordValue("Type", 1); err != nil {
		return fmt.Errorf("failed to set channel Type: %w", err)
	}
	if err := channelKey.SetStringValue("OwningPublisher", providerGUIDValue); err != nil {
		return fmt.Errorf("failed to set channel OwningPublisher: %w", err)
	}

	return nil
}

func removeRegistryTree(root registry.Key, path string) {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	children, err := key.ReadSubKeyNames(-1)
	key.Close()
	if err == nil {
		for _, child := range children {
			removeRegistryTree(root, path+`\`+child)
		}
	}
	_ = registry.DeleteKey(root, path)
}

func utf16FieldDescriptor(value []uint16) eventDataDescriptor {
	return eventDataDescriptor{
		Ptr:  uint64(uintptr(unsafe.Pointer(&value[0]))),
		Size: uint32(len(value) * 2),
	}
}

func scalarFieldDescriptor(value *uint32) eventDataDescriptor {
	return eventDataDescriptor{
		Ptr:  uint64(uintptr(unsafe.Pointer(value))),
		Size: uint32(unsafe.Sizeof(*value)),
	}
}

func marshalStructuredPayload(payload any) (string, error) {
	switch value := payload.(type) {
	case nil:
		return "null", nil
	case json.RawMessage:
		if len(value) == 0 {
			return "null", nil
		}
		if !json.Valid(value) {
			return "", fmt.Errorf("invalid structured payload JSON")
		}
		return string(value), nil
	case []byte:
		if len(value) == 0 {
			return "null", nil
		}
		if json.Valid(value) {
			return string(value), nil
		}
		encoded, err := json.Marshal(string(value))
		return string(encoded), err
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return `""`, nil
		}
		if json.Valid([]byte(trimmed)) {
			return trimmed, nil
		}
		encoded, err := json.Marshal(value)
		return string(encoded), err
	default:
		encoded, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	}
}

func parseCode(code []int) int {
	if len(code) == 0 {
		return 0
	}

	if code[0] <= 0 {
		return 0
	}

	return code[0]
}

func splitFormatCode(args []interface{}) (int, []interface{}) {
	last := args[len(args)-1]
	code, ok := last.(int)
	if !ok {
		return 0, args
	}

	return code, args[:len(args)-1]
}

// defaultLogger is initialized lazily so package import timing does not drop
// Go-originated logs if provider initialization transiently fails.
var defaultLogger *EventLogger

func packageLogger() *EventLogger {
	defaultLoggerMu.Lock()
	defer defaultLoggerMu.Unlock()

	if defaultLogger != nil {
		return defaultLogger
	}

	logger, err := NewEventLogger()
	if err != nil {
		return nil
	}

	defaultLogger = logger
	return defaultLogger
}

func Log(message string, code ...int) {
	if logger := packageLogger(); logger != nil {
		logger.Log(message, code...)
	}
}

func Logf(format string, args ...interface{}) {
	if logger := packageLogger(); logger != nil {
		logger.Logf(format, args...)
	}
}

func LogStructured(eventName string, payload any, code ...int) {
	if logger := packageLogger(); logger != nil {
		logger.LogStructured(eventName, payload, code...)
	}
}

func Warn(message string, code ...int) {
	if logger := packageLogger(); logger != nil {
		logger.Warn(message, code...)
	}
}

func Warnf(format string, args ...interface{}) {
	if logger := packageLogger(); logger != nil {
		logger.Warnf(format, args...)
	}
}

func WarnStructured(eventName string, payload any, code ...int) {
	if logger := packageLogger(); logger != nil {
		logger.WarnStructured(eventName, payload, code...)
	}
}

func Error(err error, code ...int) {
	if logger := packageLogger(); logger != nil {
		logger.Error(err, code...)
	}
}

func Errorf(format string, args ...interface{}) {
	if logger := packageLogger(); logger != nil {
		logger.Errorf(format, args...)
	}
}

func ErrorStructured(eventName string, payload any, code ...int) {
	if logger := packageLogger(); logger != nil {
		logger.ErrorStructured(eventName, payload, code...)
	}
}
