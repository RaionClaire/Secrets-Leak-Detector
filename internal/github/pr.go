package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v63/github"
	"golang.org/x/oauth2"

	"github.com/raionclaire/secrets-leak-detector/internal/scanner"
)

type prEvent struct {
	PullRequest struct {
		Number int `json:"number"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"` 
	} `json:"repository"`
}

func ghClient() (*github.Client, error) {
	tok := os.Getenv("GITHUB_TOKEN")
	if tok == "" {
		return nil, errors.New("GITHUB_TOKEN not set")
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok})
	tc := oauth2.NewClient(context.Background(), ts)
	return github.NewClient(tc), nil
}

func eventPRNumber() (owner, repo string, prNumber int, err error) {
	evPath := os.Getenv("GITHUB_EVENT_PATH")
	if evPath == "" {
		return "", "", 0, errors.New("GITHUB_EVENT_PATH not set (run inside GitHub Actions PR event)")
	}
	b, err := os.ReadFile(evPath)
	if err != nil {
		return "", "", 0, err
	}
	var e prEvent
	if err := json.Unmarshal(b, &e); err != nil {
		return "", "", 0, err
	}

	full := e.Repository.FullName
	parts := strings.Split(full, "/")
	if len(parts) != 2 {
		return "", "", 0, fmt.Errorf("bad repository full_name: %q", full)
	}
	return parts[0], parts[1], e.PullRequest.Number, nil
}

func ScanPullRequest(sc *scanner.Scanner) ([]scanner.Finding, error) {
	if os.Getenv("GITHUB_EVENT_NAME") != "pull_request" {
		return nil, errors.New("mode=pr requires pull_request event")
	}

	client, err := ghClient()
	if err != nil {
		return nil, err
	}
	owner, repo, prNum, err := eventPRNumber()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	opts := &github.ListOptions{PerPage: 100}
	var all []scanner.Finding

	for {
		files, resp, err := client.PullRequests.ListFiles(ctx, owner, repo, prNum, opts)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.GetPatch() == "" {
				continue
			}
			ff, _ := sc.ScanPatch(f.GetFilename(), f.GetPatch())
			all = append(all, ff...)
			if scOptMax(sc, len(all)) {
				return all, nil
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func scOptMax(sc *scanner.Scanner, current int) bool {
	return current >= 200
}

func CommentFindingsOnPR(findings []scanner.Finding) error {
	if os.Getenv("GITHUB_EVENT_NAME") != "pull_request" {
		return nil
	}
	client, err := ghClient()
	if err != nil {
		return err
	}
	owner, repo, prNum, err := eventPRNumber()
	if err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("🚨 **Secrets Leak Detector** finds the potential secrets in this PR:\n\n")
	max := 20
	if len(findings) < max {
		max = len(findings)
	}
	for i := 0; i < max; i++ {
		f := findings[i]
		b.WriteString(fmt.Sprintf("- **%s** in `%s` (line ~%d): `%s`\n", f.RuleID, f.File, f.Line, f.Masked))
	}
	if len(findings) > max {
		b.WriteString(fmt.Sprintf("\n…and %d more findings.\n", len(findings)-max))
	}
	b.WriteString("\n✅ Recommendation: remove secrets from code, **revoke/rotate** the tokens, then push again.\n")
	b.WriteString("\n_(This tool does not display full secret values for security reasons.)_")

	ctx := context.Background()
	_, _, err = client.Issues.CreateComment(ctx, owner, repo, prNum, &github.IssueComment{
		Body: github.String(b.String()),
	})
	return err
}
