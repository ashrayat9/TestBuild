package composer

import (
	"net/http"
	"strings"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

var (
	baseLogger = clog.NewCLog("base")
)

func parse(urlPath string) string {
	baseLogger.Infof("Parsing URL: %v", urlPath)
	parts := strings.Split(urlPath, "/")
	baseLogger.Infof("Parts: %v", parts)
	if len(parts) < 4 {
		return ""
	}
	packageName := parts[2] + "/" + parts[3]
	return packageName
}

func Handle(p *policy.Policy, r *http.Request, sess *session.Session) *session.Activity {

	if r==nil || sess==nil {
		baseLogger.Errorf("Request or session is nil")
		return session.NilActivity
	}
	baseLogger.Infof("Patterns: %v", r.URL.Path)
	if r.Host != "repo.packagist.org" && r.Host != "codeload.github.com" {
		return session.NilActivity
	}
	if r.Host == "codeload.github.com" {
		baseLogger.Infof("Package name map: %v", sess.PackageNameMap)
		value, exists := sess.PackageNameMap[strings.ToLower(strings.Split(strings.Split(r.URL.Path, "/")[2], ".")[0])]
		baseLogger.Infof("Value exists in package name map: %v", value)
		// adds package name to session activity object if it exists in PackageNameMap
		if !exists {
			return &session.Activity{
				ActivityHdr: model.ActivityHdr{
					Name:   model.Composer,
					Action: "get",
				},
				Activity: model.PackageActivity{
					Repo: r.Host,
				},
			}
		} else {
			return &session.Activity{
				ActivityHdr: model.ActivityHdr{
					Name:   model.Composer,
					Action: "get",
				},
				Activity: model.PackageActivity{
					Repo:    r.Host,
					Package: value,
				},
			}
		}
	}

	if r.Host == "repo.packagist.org" && r.URL.Path != "/downloads/" {
		// store package name in separate object so that it could be retrieved later
		PackageName := parse(r.URL.Path)
		if PackageName != "" {
			// add the last part of package name to packageNameMap, example abc\xyz (stores xyz)
			sanitizedPackageName := strings.ToLower(strings.Split(PackageName, ".json")[0])
			name := strings.Split(sanitizedPackageName, "/")[1]
			sess.PackageNameMap[name] = sanitizedPackageName
		}
		return session.NilActivity
	}
	return session.NilActivity
}
