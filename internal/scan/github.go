package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
)

type githubClient struct{ *apiClient }

func newGithubClient(base, token string) *githubClient {
	return &githubClient{newAPIClient(base, token, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Accept", "application/vnd.github+json")
		r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	})}
}

// listProjects returns the repositories reachable from the token.
//
// `affiliation` is how far "contributed to" can honestly be taken:
//   - owner               — yours, including forks of things you contributed to
//   - collaborator        — repos you were given push access to
//   - organization_member — repos of your orgs
//
// GitHub has no endpoint for "repos I once sent a PR to without access"; that
// would mean the commit search API, which is rate-limited to 30 requests a
// minute and returns commits rather than repositories. Those contributions
// almost always live in a fork you own anyway, which `owner` already covers.
//
// Archived repos are kept for the same reason as on GitLab: that is where a
// compromised lockfile is left to rot.
func (c *githubClient) listProjects(ctx context.Context, affiliations string, includeArchived bool) ([]remoteProject, error) {
	var out []remoteProject
	const perPage = 100
	for page := 1; ; page++ {
		q := url.Values{
			"affiliation": {affiliations},
			"visibility":  {"all"},
			"per_page":    {strconv.Itoa(perPage)},
			"page":        {strconv.Itoa(page)},
			"sort":        {"full_name"},
		}
		resp, err := c.get(ctx, c.base+"/user/repos?"+q.Encode())
		if err != nil {
			return out, fmt.Errorf("github: %w", err)
		}
		var batch []struct {
			FullName      string `json:"full_name"`
			CloneURL      string `json:"clone_url"`
			SSHURL        string `json:"ssh_url"`
			DefaultBranch string `json:"default_branch"`
			Archived      bool   `json:"archived"`
			Size          int    `json:"size"` // 0 means the repo has no content
		}
		err = json.NewDecoder(resp.Body).Decode(&batch)
		resp.Body.Close()
		if err != nil {
			return out, fmt.Errorf("github: decoding repos page %d: %w", page, err)
		}
		for _, r := range batch {
			if r.Archived && !includeArchived {
				continue
			}
			out = append(out, remoteProject{
				Source: "github", Name: r.FullName,
				HTTPURL: r.CloneURL, SSHURL: r.SSHURL,
				DefaultBranch: r.DefaultBranch, Empty: r.Size == 0,
				CloneURL: authenticatedURL(r.CloneURL, "x-access-token", c.token),
			})
		}
		slog.Debug("github page fetched", "page", page, "got", len(batch))
		if len(batch) < perPage {
			return out, nil
		}
	}
}
