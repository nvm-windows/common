package system

import "strings"
import "testing"

func TestAntivirusLabelNotDetected(t *testing.T) {
	orig := detectAntivirusProducts
	t.Cleanup(func() { detectAntivirusProducts = orig })
	detectAntivirusProducts = func() []string { return nil }

	if got := AntivirusLabel(); got != AntivirusNotDetected {
		t.Fatalf("AntivirusLabel() = %q", got)
	}
	if strings.Contains(AntivirusConflictSentence(), "installed") {
		t.Fatalf("sentence blamed a product: %s", AntivirusConflictSentence())
	}
	if !strings.Contains(AntivirusConflictSentence(), "Security software can lock") {
		t.Fatalf("sentence = %s", AntivirusConflictSentence())
	}
}

func TestAntivirusConflictSentenceNamesProductWithoutBlame(t *testing.T) {
	orig := detectAntivirusProducts
	t.Cleanup(func() { detectAntivirusProducts = orig })
	detectAntivirusProducts = func() []string { return []string{"Arctic Wolf Agent", "arctic wolf agent", "Windows Defender"} }

	got := AntivirusConflictSentence()
	if !strings.Contains(got, "Arctic Wolf Agent is installed") && !strings.Contains(got, "Arctic Wolf Agent, Windows Defender are installed") {
		t.Fatalf("sentence = %s", got)
	}
	if strings.Contains(strings.ToLower(got), "blocked") {
		t.Fatalf("sentence blamed the product: %s", got)
	}
}

func TestCompactAntivirusNamesDropsDuplicates(t *testing.T) {
	got := compactAntivirusNames([]string{"Windows Defender", "windows defender", "Arctic Wolf Agent"})
	if len(got) != 2 {
		t.Fatalf("names = %#v", got)
	}
}
