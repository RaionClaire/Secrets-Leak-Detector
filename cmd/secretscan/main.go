package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yourname/secrets-leak-detector/internal/github"
	"github.com/yourname/secrets-leak-detector/internal/scanner"
)

func main() {
	var (
		mode            = flag.String("mode", "repo", "scan mode: repo|pr")
		path            = flag.String("path", ".", "path to scan (repo mode)")
		configPath      = flag.String("config", ".secretscan.yml", "config file path")
		ignorePath      = flag.String("ignore", ".secretsignore", "ignore file path")
		format          = flag.String("format", "text", "output format: text|json")
		failOnFindings  = flag.Bool("fail", true, "exit non-zero if secrets found")
		commentOnPR     = flag.Bool("comment", true, "post PR comment when secrets found (pr mode)")
		maxFindings     = flag.Int("max-findings", 50, "max findings before stop")
	)
	flag.Parse()

	cfg, _ := scanner.LoadConfig(*configPath) // config optional
	ign, _ := scanner.LoadIgnoreFile(*ignorePath)

	sc := scanner.New(scanner.Options{
		Config:      cfg,
		Ignore:      ign,
		MaxFindings: *maxFindings,
	})

	var findings []scanner.Finding
	var err error

	switch strings.ToLower(*mode) {
	case "repo":
		findings, err = sc.ScanRepo(*path)
	case "pr":
		findings, err = github.ScanPullRequest(sc)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s (use repo|pr)\n", *mode)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(findings)
	} else {
		if len(findings) == 0 {
			fmt.Println("✅ No secrets detected.")
		} else {
			fmt.Printf("WARNING! Potential secrets detected:\n", len(findings))
			for _, f := range findings {
				fmt.Printf("- [%s] %s:%d  (%s)\n", f.RuleID, f.File, f.Line, f.Snippet)
			}
		}
	}

	if strings.ToLower(*mode) == "pr" && *commentOnPR && len(findings) > 0 {
		_ = github.CommentFindingsOnPR(findings)
	}

	if *failOnFindings && len(findings) > 0 {
		os.Exit(1)
	}
}
