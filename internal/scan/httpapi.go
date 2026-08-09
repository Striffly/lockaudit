package scan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// remoteProject is a repository listed by a forge API, whichever forge it was.
// The pipeline treats GitLab and GitHub identically from here on.
type remoteProject struct {
	Source        string // gitlab | github
	Name          string // group/project or owner/repo
	HTTPURL       string
	SSHURL        string
	DefaultBranch string
	Empty         bool
	CloneURL      string // http URL carrying credentials; never logged, never stored
}

// apiClient is the bit GitLab and GitHub genuinely share: authenticated GETs
// with backoff, rate-limit handling, and a token that must never reach a log.
type apiClient struct {
	base  string
	token string
	auth  func(*http.Request)
	http  *http.Client
}

func newAPIClient(base, token string, auth func(*http.Request)) *apiClient {
	return &apiClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		auth:  auth,
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

// scrub removes the token from anything about to be logged or returned as an
// error. http and git both echo back the URL they were handed.
func (c *apiClient) scrub(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "***")
}

func (c *apiClient) get(ctx context.Context, u string) (*http.Response, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		c.auth(req)
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s", c.scrub(err.Error()))
			continue
		}
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 || isRateLimited(resp):
			wait := retryAfter(resp)
			resp.Body.Close()
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			slog.Warn("forge throttled, backing off", "status", resp.StatusCode, "wait", wait)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			resp.Body.Close()
			return nil, fmt.Errorf("http %d: token invalid or missing the required read scopes", resp.StatusCode)
		case resp.StatusCode >= 400:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("http %d: %s", resp.StatusCode, c.scrub(string(body)))
		default:
			return resp, nil
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", maxAttempts, lastErr)
}

// isRateLimited spots GitHub's exhausted-quota 403, which is a "come back
// later", not the "your token is wrong" 403 handled above.
func isRateLimited(resp *http.Response) bool {
	return resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0"
}

func retryAfter(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(ts, 0)); d > 0 && d < 15*time.Minute {
				return d + time.Second
			}
		}
	}
	return 5 * time.Second
}

// authenticatedURL injects credentials into an https clone URL. The result is
// only ever passed to git as an argument — never written to a repo config.
func authenticatedURL(httpURL, user, token string) string {
	if token == "" || !strings.HasPrefix(httpURL, "https://") {
		return httpURL
	}
	return "https://" + user + ":" + token + "@" + strings.TrimPrefix(httpURL, "https://")
}
