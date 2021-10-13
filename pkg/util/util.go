package util

import "strings"

// StrSliceEqual checks wheter slice s contains a string exactly like e.
func StrSliceEqual(s []string, e string) bool {
	for _, a := range s {
		if strings.EqualFold(a, e) {
			return true
		}
	}
	return false
}

// StrSliceContains checks wheter slice s contains a string which contains e.
func StrSliceContains(s []string, e string) bool {
	for _, a := range s {
		if strings.Contains(a, e) {
			return true
		}
	}
	return false
}
