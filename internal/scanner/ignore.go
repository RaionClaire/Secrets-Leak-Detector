package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type Ignore struct {
	Globs []string
}

func LoadIgnoreFile(path string) (Ignore, error) {
	var ign Ignore
	f, err := os.Open(path)
	if err != nil {
		return ign, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ign.Globs = append(ign.Globs, line)
	}
	return ign, nil
}

func (i Ignore) Match(path string) bool {
	p := filepath.ToSlash(path)
	for _, g := range i.Globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if ok, _ := filepath.Match(g, p); ok {
			return true
		}
		if strings.Contains(p, strings.Trim(g, "*")) && (strings.Contains(g, "*") || strings.Contains(g, "/")) {
			return true
		}
	}
	return false
}
