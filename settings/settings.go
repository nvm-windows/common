package settings

import (
	prefs "common/preferences"
	"common/registry"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var AppId string
var CheckURL string
var ScheduleURL string
var semverPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
var globalSettings Settings
var loaded bool

func List() []string {
	t := reflect.TypeOf(Settings{})
	options := make([]string, 0, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		if key := t.Field(i).Tag.Get("cfg"); key != "" {
			options = append(options, key)
		}
	}

	return options
}

func Load(reload ...bool) {
	if loaded && (len(reload) == 0 || !reload[0]) {
		return
	}

	values, err := registry.GetAll(prefs.ROOTS[0])
	if err != nil {
		return
	}

	if len(prefs.ROOTS) > 1 {
		for _, root := range prefs.ROOTS[1:] {
			data, err := registry.GetAll(root)
			if err != nil {
				continue
			}

			for k, v := range data {
				if _, exists := values[k]; !exists {
					values[k] = v
				}
			}
		}
	}

	t := reflect.TypeOf(Settings{})
	s := reflect.ValueOf(&globalSettings).Elem()

	// Build a map from registry key names to field indices
	regKeyToField := make(map[string]int)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if regKey := field.Tag.Get("reg"); regKey != "" {
			regKeyToField[regKey] = i
		}
	}

	// Track which fields have been populated from registry
	populatedFromRegistry := make(map[int]bool)

	// Populate struct fields from registry values with type conversion
	for regKeyName, value := range values {
		if fieldIdx, ok := regKeyToField[regKeyName]; ok && value != nil {
			field := t.Field(fieldIdx)
			convertedValue := convertRegistryValue(value, field.Type)
			if convertedValue != nil {
				s.Field(fieldIdx).Set(reflect.ValueOf(convertedValue))
				populatedFromRegistry[fieldIdx] = true
			}
		}
	}

	// Apply defaults for unpopulated fields
	for i := 0; i < t.NumField(); i++ {
		if !populatedFromRegistry[i] {
			field := t.Field(i)
			if cfgName := field.Tag.Get("cfg"); cfgName != "" {
				defaultVal, err := DefaultValue(cfgName)
				if err == nil && defaultVal != nil {
					s.Field(i).Set(reflect.ValueOf(defaultVal))
				}
			}
		}
	}

	loaded = true
}

// convertRegistryValue converts a raw registry value to the target type.
func convertRegistryValue(value interface{}, targetType reflect.Type) interface{} {
	if value == nil {
		return nil
	}

	// Handle bool fields: registry stores them as uint32 (DWORD)
	if targetType.Kind() == reflect.Bool {
		switch v := value.(type) {
		case uint32:
			return v != 0
		case uint64:
			return v != 0
		case bool:
			return v
		case string:
			return v == "1" || strings.EqualFold(v, "true")
		default:
			return nil
		}
	}

	// Handle []string fields: convert string to []string by splitting on comma
	if targetType.Kind() == reflect.Slice && targetType.Elem().Kind() == reflect.String {
		switch v := value.(type) {
		case string:
			// Split on comma and trim whitespace from each part
			if v == "" {
				return []string{}
			}
			parts := strings.Split(v, ",")
			result := make([]string, len(parts))
			for i, part := range parts {
				result[i] = strings.TrimSpace(part)
			}
			return result
		case []string:
			return v
		case []interface{}:
			// Handle case where registry returns []interface{}
			result := make([]string, len(v))
			for i, item := range v {
				if s, ok := item.(string); ok {
					result[i] = strings.TrimSpace(s)
				}
			}
			return result
		default:
			return nil
		}
	}

	// For string fields and other types, return as-is only if type matches
	if targetType.Kind() == reflect.String {
		if normalized, ok := normalizeRegistryStringValue(value); ok {
			return normalized
		}
		return nil
	}

	return value
}

func normalizeRegistryStringValue(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case []byte:
		return strings.TrimSpace(string(v)), true
	case []string:
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item != "" {
				return item, true
			}
		}
		return "", true
	case []interface{}:
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				continue
			}
			text = strings.TrimSpace(text)
			if text != "" {
				return text, true
			}
		}
		return "", true
	default:
		return "", false
	}
}

// Global returns the currently loaded settings.
func Global() Settings {
	if !loaded {
		Load()
	}

	return globalSettings
}

// expandEnvVars expands Windows-style %VAR% environment variable references in path.
var winEnvVar = regexp.MustCompile(`%([^%]+)%`)

func Expand(path string) string {
	return winEnvVar.ReplaceAllStringFunc(path, func(match string) string {
		varName := match[1 : len(match)-1]
		if value, ok := os.LookupEnv(varName); ok {
			return value
		}
		return match
	})
}

func fieldByCfg(name string) (reflect.StructField, bool) {
	t := reflect.TypeOf(Settings{})
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("cfg") == name {
			return t.Field(i), true
		}
	}

	return reflect.StructField{}, false
}

func IsSecret(name string) bool {
	field, ok := fieldByCfg(name)
	return ok && field.Tag.Get("secret") == "true"
}

func HasChangeAudit(name string) bool {
	switch name {
	case "access_token":
		return true
	default:
		return false
	}
}

func MaskedValue(name string, value interface{}) interface{} {
	if !IsSecret(name) {
		return value
	}

	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return "(redacted)"
	case []byte:
		if strings.TrimSpace(string(v)) == "" {
			return nil
		}
		return "(redacted)"
	case []string:
		for _, item := range v {
			if strings.TrimSpace(item) != "" {
				return []string{"(redacted)"}
			}
		}
		return []string{}
	default:
		return "(redacted)"
	}
}

func comparableValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	case []string:
		trimmed := make([]string, 0, len(v))
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item != "" {
				trimmed = append(trimmed, item)
			}
		}
		return strings.Join(trimmed, ",")
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func ChangeAuditMessage(name string, currentValue, newValue interface{}) (string, bool) {
	if !HasChangeAudit(name) {
		return "", false
	}

	current := comparableValue(currentValue)
	next := comparableValue(newValue)
	if current == next {
		return "", false
	}

	if next == "" {
		return "License key cleared.", true
	}

	return "License key changed.", true
}

func DeletionAuditMessage(name string, currentValue interface{}) (string, bool) {
	if !HasChangeAudit(name) {
		return "", false
	}

	if comparableValue(currentValue) == "" {
		return "", false
	}

	return "License key cleared.", true
}

func key(name string) string {
	field, ok := fieldByCfg(name)
	if ok {
		return field.Tag.Get("reg")
	}

	return ""
}

func regkey(name string, root ...string) string {
	if len(root) > 0 {
		return root[0] + "/" + key(name)
	}

	return prefs.ROOT + "/" + key(name)
}

func policyRegKeys(name string) []string {
	regName := key(name)
	if regName == "" {
		return nil
	}

	keys := make([]string, 0, len(prefs.ROOTS))
	for _, root := range prefs.ROOTS {
		normalizedRoot := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(root), `\`, "/"))
		if strings.Contains(normalizedRoot, "/POLICIES/") {
			keys = append(keys, regkey(name, root))
		}
	}

	return keys
}

func policyValue(name string) (interface{}, bool, error) {
	keys := policyRegKeys(name)
	if len(keys) == 0 {
		return nil, false, nil
	}

	field, ok := fieldByCfg(name)
	if ok && field.Type.Kind() == reflect.Bool {
		value, exists, err := registry.GetBool(keys...)
		if err != nil || !exists {
			return nil, exists, err
		}
		return value, true, nil
	}

	value, exists, err := registry.Get(keys...)
	if err != nil || !exists {
		return nil, exists, err
	}

	if ok && field.Type.Kind() == reflect.String {
		if normalized, ok := normalizeRegistryStringValue(value); ok {
			value = normalized
		}
	}

	if name == "root" {
		if rootValue, ok := value.(string); ok {
			value = Expand(rootValue)
		}
	}

	return value, true, nil
}

func ensureNotPolicyManaged(name string) error {
	value, exists, err := policyValue(name)
	if err != nil {
		return err
	}

	if !exists {
		return nil
	}

	masked := MaskedValue(name, value)
	if comparableValue(masked) == "" {
		return fmt.Errorf("%q is managed by policy and cannot be changed", name)
	}

	return fmt.Errorf("%q is managed by policy and cannot be changed (effective value: %v)", name, masked)
}

// Validate checks whether value is acceptable for the named setting.
// It is called automatically by Put, but can also be used independently.
func Validate(name string, value interface{}) error {
	strVal := ""
	if s, ok := value.(string); ok {
		strVal = s
	}

	if field, ok := fieldByCfg(name); ok && field.Type.Kind() == reflect.Bool {
		if _, err := parseBoolInput(value); err != nil {
			return fmt.Errorf("%s must be 0, 1, true, or false", name)
		}
		return nil
	}

	switch name {
	case "mode":
		field, ok := fieldByCfg(name)
		if !ok {
			break
		}
		allowed := strings.Split(field.Tag.Get("enum"), ",")
		for _, v := range allowed {
			if strVal == v {
				return nil
			}
		}
		return fmt.Errorf("mode %q is not valid; must be one of: %s", strVal, strings.Join(allowed, ", "))

	case "root":
		if strings.TrimSpace(strVal) == "" {
			return fmt.Errorf("root must be a non-empty path")
		}

	case "proxy":
		if strings.TrimSpace(strVal) == "" {
			return nil // empty string clears the proxy
		}
		if err := validateURL(name, strVal); err != nil {
			return err
		}

	case "node_mirror", "npm_mirror":
		parts := []string{strVal}
		if strings.Contains(strVal, ",") {
			parts = strings.Split(strVal, ",")
		}
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if err := validateURL(name, part); err != nil {
				return err
			}
		}

	case "active_version":
		if strings.TrimSpace(strVal) == "" {
			return nil // empty clears the active version
		}
		if !semverPattern.MatchString(strVal) {
			return fmt.Errorf("active_version %q is not a valid semantic version (e.g. 22.0.0 or v22.0.0)", strVal)
		}

	}

	return nil
}

func validateURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s %q is not a valid URL (must include scheme and host)", field, raw)
	}
	return nil
}

func Put(name string, value interface{}) error {
	k := regkey(name)
	if k == prefs.ROOT+"/" {
		return fmt.Errorf("unknown setting %q", name)
	}

	if err := ensureNotPolicyManaged(name); err != nil {
		return err
	}

	if err := Validate(name, value); err != nil {
		return err
	}

	field, _ := fieldByCfg(name)
	var putErr error

	switch v := value.(type) {
	case string:
		if name == "access_token" {
			putErr = registry.Put([]byte(v), k)
			break
		}

		switch {
		case field.Type.Kind() == reflect.Bool:
			// Store bool settings as DWORD 0/1 in the registry.
			b, err := parseBoolInput(v)
			if err != nil {
				return fmt.Errorf("%s must be 0, 1, true, or false", name)
			}
			putErr = registry.PutBool(b, k)
		case field.Type == reflect.TypeOf([]string{}):
			// Always write slice fields as multi-string, even for a single value.
			if strings.Contains(v, ",") {
				putErr = registry.Put(strings.Split(v, ","), k)
			} else {
				putErr = registry.Put([]string{v}, k)
			}
		default:
			putErr = registry.Put(v, k)
		}
	case bool:
		putErr = registry.PutBool(v, k)
	default:
		return fmt.Errorf("unsupported value type %T for setting %q", value, name)
	}

	if putErr != nil {
		return putErr
	}

	// After recording root, ensure the directory exists.
	if name == "root" {
		if err := os.MkdirAll(strings.TrimSpace(value.(string)), 0755); err != nil {
			return fmt.Errorf("root: could not create \"%s\" directory: %w", strings.TrimSpace(value.(string)), err)
		}
	}

	return nil
}

func Get(name string) (interface{}, error) {
	regName := key(name)
	if regName == "" {
		return nil, fmt.Errorf("unknown setting %q", name)
	}

	keys := make([]string, 0, len(prefs.ROOTS))
	for _, root := range prefs.ROOTS {
		keys = append(keys, regkey(name, root))
	}

	if len(keys) == 0 {
		keys = append(keys, regkey(name))
	}

	field, ok := fieldByCfg(name)

	// Bool fields are stored as DWORDs; use the bool-aware getter so callers
	// always receive a typed bool rather than a raw uint32.
	if ok && field.Type.Kind() == reflect.Bool {
		value, exists, err := registry.GetBool(keys...)
		if err != nil {
			return nil, err
		}
		if exists {
			return value, nil
		}
		return DefaultValue(name)
	}

	value, exists, err := registry.Get(keys...)
	if err != nil {
		return nil, err
	}

	if exists && value != nil {
		if field, ok := fieldByCfg(name); ok && field.Type.Kind() == reflect.String {
			if normalized, ok := normalizeRegistryStringValue(value); ok {
				value = normalized
			}
		}

		if name == "root" {
			value = Expand(value.(string))
		}

		return value, nil
	}

	return DefaultValue(name)
}

func Del(name string) error {
	k := regkey(name)
	if k == prefs.ROOT+"/" {
		return fmt.Errorf("unknown setting %q", name)
	}

	if err := ensureNotPolicyManaged(name); err != nil {
		return err
	}

	return registry.Del(k)
}

func All(name string, includeHidden ...bool) (map[string]interface{}, error) {
	showHidden := false
	if len(includeHidden) > 0 {
		showHidden = includeHidden[0]
	}

	t := reflect.TypeOf(Settings{})
	values := make(map[string]interface{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if key := field.Tag.Get("cfg"); key != "" {
			hide := field.Tag.Get("hidden") == "true"
			if hide && !showHidden {
				continue
			}
			value, err := Get(key)
			if err != nil {
				return nil, fmt.Errorf("error retrieving setting %q: %w", key, err)
			}
			values[key] = value
		}
	}

	return values, nil
}

func DefaultValue(name string) (interface{}, error) {
	field, ok := fieldByCfg(name)
	if !ok {
		return nil, fmt.Errorf("unknown setting %q", name)
	}

	defaultRaw := strings.TrimSpace(field.Tag.Get("default"))
	if defaultRaw == "" {
		return nil, nil
	}

	switch field.Type.Kind() {
	case reflect.Bool:
		value, err := strconv.ParseBool(defaultRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid default bool for setting %q: %w", name, err)
		}
		return value, nil
	case reflect.Slice:
		// Handle []string defaults by splitting on comma
		if field.Type.Elem().Kind() == reflect.String {
			parts := strings.Split(defaultRaw, ",")
			result := make([]string, len(parts))
			for i, part := range parts {
				result[i] = strings.TrimSpace(part)
			}
			return result, nil
		}
		return defaultRaw, nil
	default:
		if name == "root" || name == "local_dir" {
			return Expand(defaultRaw), nil
		}

		return defaultRaw, nil
	}
}

func parseBoolInput(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		switch s {
		case "1", "true":
			return true, nil
		case "0", "false":
			return false, nil
		default:
			return false, fmt.Errorf("invalid bool input")
		}
	default:
		return false, fmt.Errorf("invalid bool input type")
	}
}

func Values(includeHidden ...bool) (map[string]interface{}, error) {
	showHidden := false
	if len(includeHidden) > 0 {
		showHidden = includeHidden[0]
	}

	s := Global()
	t := reflect.TypeOf(s)
	v := reflect.ValueOf(s)

	values := make(map[string]interface{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		key := field.Tag.Get("reg")
		if key == "" {
			continue
		}

		hide := field.Tag.Get("hidden") == "true"
		if hide && !showHidden {
			continue
		}

		values[key] = v.Field(i).Interface()
	}

	return values, nil
}
