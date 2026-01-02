package scanner

import (
	"math"
	"regexp"
	"strings"
)

func Entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	l := float64(len([]rune(s)))
	for _, c := range freq {
		p := float64(c) / l
		ent += -p * math.Log2(p)
	}
	return ent
}

var candRe = regexp.MustCompile(`[A-Za-z0-9_/\-+=]{20,}`)

func ExtractCandidates(line string, minLen int) []string {
	if minLen < 20 {
		minLen = 20
	}
	m := candRe.FindAllString(line, -1)
	out := make([]string, 0, len(m))
	for _, x := range m {
		if len(x) >= minLen {
			out = append(out, x)
		}
	}
	return out
}

var uuidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var shaRe = regexp.MustCompile(`(?i)^[0-9a-f]{32,64}$`)

func LooksLikeUUIDOrHash(s string) bool {
	ss := strings.TrimSpace(s)
	return uuidRe.MatchString(ss) || shaRe.MatchString(ss)
}

func Mask(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func Snippet(line string, match string) string {
	x := strings.ReplaceAll(line, match, Mask(match))
	x = strings.TrimSpace(x)
	if len(x) > 160 {
		return x[:160] + "…"
	}
	return x
}

func MatchAllowlist(rx string, val string) bool {
	re, err := regexp.Compile(rx)
	if err != nil {
		return false
	}
	return re.MatchString(val)
}
