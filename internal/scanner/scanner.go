package scanner

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Options struct {
	Config      Config
	Ignore      Ignore
	MaxFindings int
}

type Scanner struct {
	opt      Options
	patterns []Pattern
}

type Finding struct {
	RuleID  string `json:"ruleId"`
	Title   string `json:"title"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
	Masked  string `json:"masked"`
}

func New(opt Options) *Scanner {
	pats := DefaultPatterns()
	return &Scanner{opt: opt, patterns: pats}
}

func (s *Scanner) shouldIgnore(path string) bool {
	p := filepath.ToSlash(path)

	if s.opt.Ignore.Match(p) {
		return true
	}

	base := filepath.Base(p)
	if base == ".git" || strings.HasPrefix(p, ".git/") {
		return true
	}

	for _, ex := range s.opt.Config.ExcludeDirs {
		ex = filepath.ToSlash(strings.TrimSuffix(ex, "/"))
		if ex == "" {
			continue
		}
		if p == ex || strings.HasPrefix(p, ex+"/") {
			return true
		}
	}

	return false
}

func (s *Scanner) ScanRepo(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable path
		}
		rel := path
		if root != "." {
			if r, e := filepath.Rel(root, path); e == nil {
				rel = r
			}
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if s.shouldIgnore(rel) {
				return filepath.SkipDir
			}
			return nil
		}

		if s.shouldIgnore(rel) {
			return nil
		}

		info, e := d.Info()
		if e == nil && s.opt.Config.MaxFileSizeBytes > 0 && info.Size() > int64(s.opt.Config.MaxFileSizeBytes) {
			return nil
		}

		fileFindings, _ := s.scanFile(path, rel)
		findings = append(findings, fileFindings...)
		if s.opt.MaxFindings > 0 && len(findings) >= s.opt.MaxFindings {
			return errors.New("max findings reached")
		}
		return nil
	})
	if err != nil && err.Error() == "max findings reached" {
		return findings, nil
	}
	return findings, nil
}

func (s *Scanner) ScanPatch(filename string, patch string) ([]Finding, error) {
	var findings []Finding
	lines := strings.Split(patch, "\n")

	lineNo := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, "@@") {
			lineNo = 0
			continue
		}
		if strings.HasPrefix(ln, "+++") || strings.HasPrefix(ln, "---") {
			continue
		}
		if strings.HasPrefix(ln, "+") && !strings.HasPrefix(ln, "+++") {
			lineNo++
			text := strings.TrimPrefix(ln, "+")
			f := s.scanLine(filename, lineNo, text)
			findings = append(findings, f...)
			if s.opt.MaxFindings > 0 && len(findings) >= s.opt.MaxFindings {
				break
			}
		}
	}
	return findings, nil
}

func (s *Scanner) scanFile(absPath, relPath string) ([]Finding, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, 8000)
	n, _ := f.Read(head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return nil, nil
	}
	_, _ = f.Seek(0, io.SeekStart)

	var findings []Finding
	scn := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scn.Buffer(buf, 2*1024*1024)

	lineNo := 0
	for scn.Scan() {
		lineNo++
		line := scn.Text()
		ff := s.scanLine(relPath, lineNo, line)
		findings = append(findings, ff...)
		if s.opt.MaxFindings > 0 && len(findings) >= s.opt.MaxFindings {
			break
		}
	}
	return findings, nil
}

func (s *Scanner) scanLine(file string, lineNo int, line string) []Finding {
	trim := strings.TrimSpace(line)
	if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
		return nil
	}

	var findings []Finding

	for _, p := range s.patterns {
		matches := p.Re.FindAllStringSubmatchIndex(line, -1)
		for _, m := range matches {
			val := line[m[0]:m[1]]
			if s.opt.Config.AllowlistRegex != "" && MatchAllowlist(s.opt.Config.AllowlistRegex, val) {
				continue
			}
			findings = append(findings, Finding{
				RuleID:  p.ID,
				Title:   p.Title,
				File:    file,
				Line:    lineNo,
				Snippet: Snippet(line, val),
				Masked:  Mask(val),
			})
		}
	}

	if s.opt.Config.EnableEntropy {
		cands := ExtractCandidates(line, s.opt.Config.MinEntropyLen)
		for _, c := range cands {
			if LooksLikeUUIDOrHash(c) {
				continue
			}
			e := Entropy(c)
			if e >= s.opt.Config.EntropyThreshold {
				findings = append(findings, Finding{
					RuleID:  "ENTROPY_HIGH",
					Title:   "High entropy string (possible secret)",
					File:    file,
					Line:    lineNo,
					Snippet: Snippet(line, c),
					Masked:  Mask(c),
				})
			}
		}
	}

	return findings
}
