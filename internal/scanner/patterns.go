package scanner

import "regexp"

type Pattern struct {
	ID    string
	Title string
	Re    *regexp.Regexp
}

func DefaultPatterns() []Pattern {
	return []Pattern{
		{ID: "AWS_ACCESS_KEY_ID", Title: "AWS Access Key ID", Re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{ID: "AWS_SECRET_ACCESS_KEY", Title: "AWS Secret Access Key (generic)", Re: regexp.MustCompile(`(?i)\baws_secret_access_key\b\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`)},
		{ID: "GITHUB_PAT_CLASSIC", Title: "GitHub Token (ghp_)", Re: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
		{ID: "GITHUB_PAT_FINEGRAIN", Title: "GitHub Token (github_pat_)", Re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`)},
		{ID: "GOOGLE_API_KEY", Title: "Google API Key (AIza)", Re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
		{ID: "SLACK_TOKEN", Title: "Slack Token", Re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,200}\b`)},
		{ID: "PRIVATE_KEY_BLOCK", Title: "Private Key Block", Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----`)},
		{ID: "GENERIC_PASSWORD_ASSIGN", Title: "Hardcoded password assignment", Re: regexp.MustCompile(`(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{6,}['"]`)},
		{ID: "GENERIC_SECRET_ASSIGN", Title: "Hardcoded secret assignment", Re: regexp.MustCompile(`(?i)\b(secret|api[_-]?key|token)\b\s*[:=]\s*['"][^'"]{8,}['"]`)},
		{ID: "AXIOS_BASEURL_HARDCODED", Title: "Axios baseURL hardcoded (should use env)", Re: regexp.MustCompile(`(?i)\baxios\.create\s*\(\s*\{[\s\S]*?\bbaseURL\b\s*:\s*['"]https?://[^'"]+['"]`)},
		{ID: "AXIOS_DEFAULTS_BASEURL_HARDCODED", Title: "Axios defaults.baseURL hardcoded (should use env)", Re: regexp.MustCompile(`(?i)\baxios\.defaults\.baseURL\b\s*=\s*['"]https?://[^'"]+['"]`)},
		{ID: "AXIOS_ABSOLUTE_URL_CALL", Title: "Axios absolute URL in request (review if backend URL hardcoded)", Re: regexp.MustCompile(`(?i)\baxios\.(get|post|put|patch|delete|request)\s*\(\s*['"]https?://[^'"]+['"]`)},
	}
}
