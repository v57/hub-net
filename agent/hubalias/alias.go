// Package hubalias owns stable local Hub alias allocation.
package hubalias

import (
	"regexp"
	"strconv"
	"strings"
)

var invalidCharacters = regexp.MustCompile(`[^a-z0-9-]+`)

func Normalize(name string) string {
	normalized := strings.Trim(invalidCharacters.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
	if normalized == "" {
		return "hub"
	}
	return normalized
}

// Allocate returns the first free deterministic alias. A trailing positive
// integer is sequence notation only after the first candidate collides.
func Allocate(name string, existing []string) string {
	first := Normalize(name)
	used := make(map[string]struct{}, len(existing))
	for _, value := range existing {
		used[strings.ToLower(value)] = struct{}{}
	}
	if _, found := used[first]; !found {
		return first
	}
	base := first
	if dash := strings.LastIndex(base, "-"); dash > 0 {
		if sequence, err := strconv.Atoi(base[dash+1:]); err == nil && sequence > 0 {
			base = base[:dash]
		}
	}
	for sequence := 2; ; sequence++ {
		candidate := base + "-" + strconv.Itoa(sequence)
		if _, found := used[candidate]; !found {
			return candidate
		}
	}
}
