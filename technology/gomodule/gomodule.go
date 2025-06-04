package gomodule

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

// {web https://proxy.golang.org/github.com/kairoaraujo/goca/@v/v1.1.3.zip GET 0}

func parse(url string) (string, string, bool) {
	if !strings.HasSuffix(url, ".zip") {
		return "", "", false
	}
	url = url[:len(url)-len(".zip")]
	parts := strings.SplitN(url, "/@v/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	pack := strings.Trim(parts[0], "/")
	version := strings.Trim(parts[1], "/")
	return pack, version, true

}
func Handle(p *policy.Policy, path string, r *http.Request) *session.Activity {
	pkg, ver, act := parse(path)
	if !act {
		return session.NilActivity
	}
	purl := fmt.Sprintf("pkg:%s/%s@%s", model.GoModule, pkg, ver)
	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.GoModule,
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
