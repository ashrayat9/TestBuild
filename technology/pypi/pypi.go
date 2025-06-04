package pypi

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

func parse(url string) (string, string, bool) {

	filename := path.Base(url)
	parts := strings.Split(filename, "-")
	if len(parts) < 3 {
		return "", "", false
	}

	versionIndex := -1
	for i, part := range parts {
		// Assumes the version starts with a digit/number
		if strings.HasPrefix(part, "0") || strings.HasPrefix(part, "1") || strings.HasPrefix(part, "2") ||
			strings.HasPrefix(part, "3") || strings.HasPrefix(part, "4") || strings.HasPrefix(part, "5") ||
			strings.HasPrefix(part, "6") || strings.HasPrefix(part, "7") || strings.HasPrefix(part, "8") ||
			strings.HasPrefix(part, "9") {
			versionIndex = i
			break
		}
	}

	if versionIndex == -1 {
		return "", "", false
	}
	pkg := strings.Join(parts[:versionIndex], "-")
	ver := parts[versionIndex]
	return pkg, ver, true

}

func Handle(p *policy.Policy, path string, r *http.Request) *session.Activity {

	if r.Host != "files.pythonhosted.org" {
		return session.NilActivity
	}

	pkg, ver, act := parse(path)

	if !act {
		return session.NilActivity
	}
	purl := fmt.Sprintf("pkg:%s/%s@%s", model.Pypi, pkg, ver)
	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.Pypi,
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
