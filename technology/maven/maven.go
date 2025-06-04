package maven

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

func parse(url string) (string, string, bool) {
	if !strings.HasSuffix(url, ".jar") {
		return "", "", false
	}
	parts := strings.Split(url, "/")
	if len(parts) < 3 {
		return "", "", false
	}
	pkg := strings.Join(parts[1:len(parts)-2], ".")
	rev := parts[len(parts)-2]
	return pkg, rev, true
}

func Handle(p *policy.Policy, path string, r *http.Request) *session.Activity {
	pkg, ver, act := parse(path)
	if !act {
		return session.NilActivity
	}
	purl := fmt.Sprintf("pkg:%s/%s@%s", model.Maven, pkg, ver)
	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.Maven,
			Action: "get",
		},
		Activity: model.PackageActivity{
			Repo:    r.Host,
			Package: pkg,
			Version: ver,
			Purl:    purl,
		},
	}
}
