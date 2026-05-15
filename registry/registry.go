package registry

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	winreg "golang.org/x/sys/windows/registry"
)

func Get(key ...string) (interface{}, bool, error) {
	for _, candidate := range key {
		value, exists, err := lookup(candidate)
		if err != nil {
			if isPermissionError(err) {
				continue
			}

			return nil, false, err
		}

		if exists {
			return value, true, nil
		}
	}

	return nil, false, nil
}

// GetSubKeys returns the names of all subkeys under a registry key path.
func GetSubKeys(keyPath string) ([]string, error) {
	root, path, err := parseRegistryPath(keyPath)
	if err != nil {
		return nil, err
	}

	handle, err := winreg.OpenKey(root, path, winreg.QUERY_VALUE|winreg.ENUMERATE_SUB_KEYS)
	if err != nil {
		if isNotFoundError(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer handle.Close()

	names, err := handle.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	return names, nil
}

// GetAll returns all values under a registry key path as a flat map.
func GetAll(keyPath string) (map[string]interface{}, error) {
	root, path, err := parseRegistryPath(keyPath)
	if err != nil {
		return nil, err
	}

	handle, err := winreg.OpenKey(root, path, winreg.QUERY_VALUE|winreg.ENUMERATE_SUB_KEYS)
	if err != nil {
		if isNotFoundError(err) {
			return make(map[string]interface{}), nil
		}
		return nil, err
	}
	defer handle.Close()

	return readRegistryValues(handle)
}

func GetBool(key ...string) (bool, bool, error) {
	value, exists, err := Get(key...)
	if err != nil || !exists {
		return false, exists, err
	}

	switch v := value.(type) {
	case bool:
		return v, true, nil
	case uint64:
		return v != 0, true, nil
	case uint32:
		return v != 0, true, nil
	case int64:
		return v != 0, true, nil
	case int32:
		return v != 0, true, nil
	case string:
		normalized := strings.TrimSpace(strings.ToLower(v))
		if normalized == "" {
			return false, true, nil
		}

		if b, parseErr := strconv.ParseBool(normalized); parseErr == nil {
			return b, true, nil
		}

		if i, parseErr := strconv.ParseInt(normalized, 10, 64); parseErr == nil {
			return i != 0, true, nil
		}

		return false, true, fmt.Errorf("registry: cannot convert value %q to bool", v)
	default:
		return false, true, fmt.Errorf("registry: unsupported bool conversion for type %T", value)
	}
}

func Put(value interface{}, key ...string) error {
	for _, candidate := range key {
		root, keyPath, valueName, err := parseRegistryValuePath(candidate)
		if err != nil {
			return err
		}

		handle, _, err := winreg.CreateKey(root, keyPath, winreg.SET_VALUE)
		if err != nil {
			if isPermissionError(err) {
				continue
			}

			return err
		}

		setErr := setRegistryValue(handle, valueName, value)
		handle.Close()
		if setErr != nil {
			if isPermissionError(setErr) {
				continue
			}

			return setErr
		}
	}

	return nil
}

func PutBool(value bool, key ...string) error {
	if value {
		return Put(uint32(1), key...)
	}

	return Put(uint32(0), key...)
}

func Del(key ...string) error {
	for _, candidate := range key {
		root, keyPath, valueName, err := parseRegistryValuePath(candidate)
		if err != nil {
			return err
		}

		handle, err := winreg.OpenKey(root, keyPath, winreg.SET_VALUE)
		if err != nil {
			if isNotFoundError(err) || isPermissionError(err) {
				continue
			}

			return err
		}

		deleteErr := handle.DeleteValue(valueName)
		handle.Close()
		if deleteErr != nil {
			if isNotFoundError(deleteErr) || isPermissionError(deleteErr) {
				continue
			}

			return deleteErr
		}
	}

	return nil
}

func lookup(key string) (interface{}, bool, error) {
	root, keyPath, err := parseRegistryPath(key)
	if err != nil {
		return nil, false, err
	}

	if tree, exists, err := lookupKey(root, keyPath); err != nil {
		return nil, false, err
	} else if exists {
		return tree, true, nil
	}

	root, keyPath, valueName, err := parseRegistryValuePath(key)
	if err != nil {
		return nil, false, err
	}

	handle, err := winreg.OpenKey(root, keyPath, winreg.QUERY_VALUE)
	if err != nil {
		if isNotFoundError(err) {
			return nil, false, nil
		}

		return nil, false, err
	}
	defer handle.Close()

	value, err := tryReadRegistryValue(handle, valueName)
	if err != nil {
		if isNotFoundError(err) {
			return nil, false, nil
		}

		return nil, false, err
	}

	return value, true, nil
}

func lookupKey(root winreg.Key, keyPath string) (map[string]interface{}, bool, error) {
	handle, err := winreg.OpenKey(root, keyPath, winreg.QUERY_VALUE|winreg.ENUMERATE_SUB_KEYS)
	if err != nil {
		if isNotFoundError(err) {
			return nil, false, nil
		}

		return nil, false, err
	}
	defer handle.Close()

	data, err := readRegistryTree(root, keyPath)
	if err != nil {
		return nil, false, err
	}

	return data, true, nil
}

func parseRegistryPath(source string) (winreg.Key, string, error) {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return 0, "", errors.New("registry: key path is required")
	}

	normalized := strings.ReplaceAll(trimmed, "/", "\\")
	parts := strings.SplitN(normalized, "\\", 2)
	rootLabel := strings.TrimSuffix(strings.ToUpper(strings.TrimSpace(parts[0])), ":")

	root, ok := registryRootKeys()[rootLabel]
	if !ok {
		return 0, "", fmt.Errorf("registry: unsupported registry root %q", rootLabel)
	}

	if len(parts) == 1 {
		return root, "", nil
	}

	remainder := strings.TrimLeft(strings.TrimSpace(parts[1]), "\\")
	return root, remainder, nil
}

func parseRegistryValuePath(source string) (winreg.Key, string, string, error) {
	root, remainder, err := parseRegistryPath(source)
	if err != nil {
		return 0, "", "", err
	}

	if remainder == "" {
		return 0, "", "", fmt.Errorf("registry: path %q must include key path and value name", source)
	}

	keyPath, valueName := splitKeyAndValueName(remainder)
	if valueName == "" {
		return 0, "", "", fmt.Errorf("registry: path %q must end with a value name", source)
	}

	return root, keyPath, valueName, nil
}

func splitKeyAndValueName(path string) (string, string) {
	lastBackslash := strings.LastIndex(path, "\\")
	if lastBackslash == -1 {
		return "", strings.TrimSpace(path)
	}

	keyPath := strings.TrimSpace(path[:lastBackslash])
	valueName := strings.TrimSpace(path[lastBackslash+1:])

	return keyPath, valueName
}

func registryRootKeys() map[string]winreg.Key {
	return map[string]winreg.Key{
		"HKEY_LOCAL_MACHINE":  winreg.LOCAL_MACHINE,
		"HKLM":                winreg.LOCAL_MACHINE,
		"HKEY_CURRENT_USER":   winreg.CURRENT_USER,
		"HKCU":                winreg.CURRENT_USER,
		"HKEY_CLASSES_ROOT":   winreg.CLASSES_ROOT,
		"HKCR":                winreg.CLASSES_ROOT,
		"HKEY_USERS":          winreg.USERS,
		"HKU":                 winreg.USERS,
		"HKEY_CURRENT_CONFIG": winreg.CURRENT_CONFIG,
		"HKCC":                winreg.CURRENT_CONFIG,
	}
}

func readRegistryTree(root winreg.Key, path string) (map[string]interface{}, error) {
	handle, err := winreg.OpenKey(root, path, winreg.QUERY_VALUE|winreg.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	node := map[string]interface{}{}

	values, err := readRegistryValues(handle)
	if err != nil && !isPermissionError(err) {
		return nil, err
	}
	if len(values) > 0 {
		node["values"] = values
	}

	subkeys, err := handle.ReadSubKeyNames(-1)
	if err != nil {
		if isPermissionError(err) {
			return node, nil
		}
		return nil, err
	}

	for _, name := range subkeys {
		childPath := name
		if path != "" {
			childPath = path + "\\" + name
		}

		child, err := readRegistryTree(root, childPath)
		if err != nil {
			if isPermissionError(err) {
				continue
			}
			return nil, err
		}
		node[name] = child
	}

	return node, nil
}

func readRegistryValues(key winreg.Key) (map[string]interface{}, error) {
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	values := make(map[string]interface{}, len(names))
	for _, name := range names {
		displayName := name
		if displayName == "" {
			displayName = "(Default)"
		}

		value, err := tryReadRegistryValue(key, name)
		if err != nil {
			if isPermissionError(err) {
				continue
			}
			return nil, err
		}

		values[displayName] = value
	}

	return values, nil
}

func tryReadRegistryValue(key winreg.Key, name string) (interface{}, error) {
	if value, _, err := key.GetStringsValue(name); err == nil {
		return value, nil
	}

	if value, _, err := key.GetStringValue(name); err == nil {
		return value, nil
	}

	if value, _, err := key.GetIntegerValue(name); err == nil {
		return value, nil
	}

	if value, _, err := key.GetBinaryValue(name); err == nil {
		return value, nil
	}

	return nil, winreg.ErrNotExist
}

func setRegistryValue(key winreg.Key, name string, value interface{}) error {
	switch v := value.(type) {
	case string:
		return key.SetStringValue(name, v)
	case []string:
		return key.SetStringsValue(name, v)
	case []byte:
		return key.SetBinaryValue(name, v)
	case bool:
		if v {
			return key.SetDWordValue(name, 1)
		}
		return key.SetDWordValue(name, 0)
	case uint32:
		return key.SetDWordValue(name, v)
	case uint64:
		if v <= uint64(^uint32(0)) {
			return key.SetDWordValue(name, uint32(v))
		}
		return key.SetQWordValue(name, v)
	case uint:
		if uint64(v) <= uint64(^uint32(0)) {
			return key.SetDWordValue(name, uint32(v))
		}
		return key.SetQWordValue(name, uint64(v))
	case int:
		if v < 0 {
			return fmt.Errorf("registry: negative integers are not supported for DWORD/QWORD values")
		}
		return setRegistryValue(key, name, uint64(v))
	case int32:
		if v < 0 {
			return fmt.Errorf("registry: negative integers are not supported for DWORD/QWORD values")
		}
		return key.SetDWordValue(name, uint32(v))
	case int64:
		if v < 0 {
			return fmt.Errorf("registry: negative integers are not supported for DWORD/QWORD values")
		}
		return setRegistryValue(key, name, uint64(v))
	default:
		return fmt.Errorf("registry: unsupported value type %T", value)
	}
}

func isNotFoundError(err error) bool {
	return errors.Is(err, winreg.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND)
}

func isPermissionError(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}
