package jsd

import "regexp"

var rtRe = regexp.MustCompile(`r:'([^']+)',t:'([^']+)'`)

func ExtractRT(s string) *Extracted {
	m := rtRe.FindStringSubmatch(s)
	if len(m) == 3 {
		return &Extracted{
			r: m[1],
			t: m[2],
		}
	}
	return nil
}
