package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

type gitlabClient struct{ *apiClient }

func newGitlabClient(base, token string) *gitlabClient {
	return &gitlabClient{newAPIClient(base, token, func(r *http.Request) {
		r.Header.Set("PRIVATE-TOKEN", token)
		r.Header.Set("Accept", "application/json")
	})}
}

// listProjects returns every project the token's user is a member of.
//
// Offset pagination: GitLab reports the next page in X-Next-Page and sends an
// empty value on the last one. Archived projects are deliberately NOT filtered
// out — an archived project is exactly where a compromised lockfile goes to be
// forgotten. Empty repos are dropped: there is nothing to clone.
func (c *gitlabClient) listProjects(ctx context.Context, includeArchived bool) ([]remoteProject, error) {
	var out []remoteProject
	page := "1"
	for page != "" {
		q := url.Values{
			"membership": {"true"},
			"per_page":   {"100"},
			"order_by":   {"id"},
			"sort":       {"asc"},
			"page":       {page},
		}
		if !includeArchived {
			q.Set("archived", "false")
		}
		resp, err := c.get(ctx, c.base+"/api/v4/projects?"+q.Encode())
		if err != nil {
			return out, fmt.Errorf("gitlab: %w", err)
		}
		var batch []struct {
			PathWithNamespace string `json:"path_with_namespace"`
			HTTPURL           string `json:"http_url_to_repo"`
			SSHURL            string `json:"ssh_url_to_repo"`
			DefaultBranch     string `json:"default_branch"`
			EmptyRepo         bool   `json:"empty_repo"`
		}
		err = json.NewDecoder(resp.Body).Decode(&batch)
		total := resp.Header.Get("X-Total")
		next := resp.Header.Get("X-Next-Page")
		resp.Body.Close()
		if err != nil {
			return out, fmt.Errorf("gitlab: decoding projects page %s: %w", page, err)
		}
		for _, p := range batch {
			out = append(out, remoteProject{
				Source: "gitlab", Name: p.PathWithNamespace,
				HTTPURL: p.HTTPURL, SSHURL: p.SSHURL,
				DefaultBranch: p.DefaultBranch, Empty: p.EmptyRepo,
				CloneURL: authenticatedURL(p.HTTPURL, "oauth2", c.token),
			})
		}
		slog.Debug("gitlab page fetched", "page", page, "got", len(batch), "total", total)
		if len(batch) == 0 {
			break
		}
		page = next
	}
	return out, nil
}
