package modulefirewall

import (
	"fmt"
	"io"
	"strings"
)

const humanListCap = 20

// FormatHumanList writes up to 20 lines then "and N more". Empty input is a no-op.
func FormatHumanList(w io.Writer, lines []string) {
	if len(lines) == 0 {
		return
	}
	n := len(lines)
	limit := humanListCap
	if n < limit {
		limit = n
	}
	for i := 0; i < limit; i++ {
		fmt.Fprintln(w, lines[i])
	}
	if n > humanListCap {
		fmt.Fprintf(w, "and %d more\n", n-humanListCap)
	}
}

// CapHumanStrings returns a copy capped at 20 with a trailing "and N more" entry when needed.
func CapHumanStrings(items []string) []string {
	if len(items) <= humanListCap {
		out := make([]string, len(items))
		copy(out, items)
		return out
	}
	out := make([]string, 0, humanListCap+1)
	out = append(out, items[:humanListCap]...)
	out = append(out, fmt.Sprintf("and %d more", len(items)-humanListCap))
	return out
}

// FormatBlockedLines builds human lines for package blocks (name + optional reason).
func FormatBlockedLines(pkgs []PackageSpec, reason string) []string {
	reason = strings.TrimSpace(reason)
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		name := p.Raw
		if name == "" {
			name = p.Name
		}
		if reason == "" {
			out = append(out, name)
		} else {
			out = append(out, name+"\t"+reason)
		}
	}
	return out
}
