package system

import "strings"

// AntivirusNotDetected is the machine-details value when Windows reports no antivirus product.
const AntivirusNotDetected = "Not Detected"

// detectAntivirusProducts is set by the OS-specific file.
var detectAntivirusProducts func() []string

// AntivirusLabel returns registered antivirus product names.
// It returns AntivirusNotDetected when Security Center and known agents provide no names.
func AntivirusLabel() string {
	if detectAntivirusProducts == nil {
		return AntivirusNotDetected
	}
	names := compactAntivirusNames(detectAntivirusProducts())
	if len(names) == 0 {
		return AntivirusNotDetected
	}
	return strings.Join(names, ", ")
}

// AntivirusConflictSentence names installed products without claiming they caused a failure.
func AntivirusConflictSentence() string {
	label := AntivirusLabel()
	if label == AntivirusNotDetected {
		return "Security software can lock this key store during npm upgrade."
	}
	verb := "is"
	if strings.Contains(label, ",") {
		verb = "are"
	}
	return label + " " + verb + " installed. Security software can lock this key store during npm upgrade."
}

func compactAntivirusNames(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		dup := false
		for _, existing := range seen {
			if existing == key || strings.Contains(existing, key) || strings.Contains(key, existing) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		seen = append(seen, key)
		out = append(out, name)
	}
	return out
}
