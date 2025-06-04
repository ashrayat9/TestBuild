package git

import (
	"net/http"
	"strings"

	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

func Handle(p *policy.Policy, path string, r *http.Request) *session.Activity {
	parts := strings.SplitN(path, "/", 4)
	if len(parts) >= 4 {
		repo := strings.Join([]string{r.Host, parts[1], parts[2]}, "/")
		// identity git action based on request query param
		queryParams := r.URL.Query()
		service_query := queryParams.Get("service")

		action := ""
		switch {
		case parts[3] == "git-upload-pack" || service_query == "git-upload-pack":
			action = "pull"
		case parts[3] == "git-receive-pack" || service_query == "git-receive-pack":
			action = "push"
		}

		repo = strings.TrimSuffix(repo, ".git")
		if action != "" {
			return &model.Activity{
				ActivityHdr: model.ActivityHdr{
					Name:   model.Git,
					Action: action,
				},
				Activity: model.GitActivity{
					Repo: repo,
				},
			}
		}

	}
	return session.NilActivity
}
