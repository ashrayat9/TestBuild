package nuget

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

// Example NuGet URL patterns:
// 1. Official NuGet v3 feed:
//    - https://api.nuget.org/v3/flatcontainer/{package_id}/{version}/{package_id}.{version}.nupkg
//    - https://api.nuget.org/v3/flatcontainer/{package_id}/{version}/{package_id}.{version}.nuspec
//    - Example: https://api.nuget.org/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg
//
// 2. Official NuGet v2 feed (legacy, but might still be encountered):
//    - https://www.nuget.org/api/v2/package/{package_id}/{version}
//    - Example: https://www.nuget.org/api/v2/package/Newtonsoft.Json/13.0.1
//
// 3. Azure DevOps Artifacts (common for private feeds):
//    - https://pkgs.dev.azure.com/{organization}/{project}/_packaging/{feed_name}/nuget/v3/flat2/{package_id_lowercase}/{version}/{package_id_lowercase}.{version}.nupkg
//    - https://pkgs.dev.azure.com/{organization}/{project}/_packaging/{feed_name}/nuget/v3/flatcontainer/{package_id_lowercase}/{version}/{package_id_lowercase}.{version}.nupkg
//    - Example: https://pkgs.dev.azure.com/myorg/myproject/_packaging/MyFeed/nuget/v3/flat2/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg
//
// 4. Other potential patterns (e.g., Artifactory, MyGet - general structure often similar to v3 or v2):
//    - {hostname}/artifactory/api/nuget/{feed_name}/{package_id}/{version}/{package_id}.{version}.nupkg
//    - {hostname}/F/{feed_name}/api/v2/package/{package_id}/{version}
//    - {hostname}/F/{feed_name}/api/v3/flatcontainer/{package_id}/{version}/{package_id}.{version}.nupkg

var (
	nuGetV3FlatPattern    = regexp.MustCompile(`(?i)/([^/]+)/([^/]+)/[^/]+\.(nupkg|nuspec)$`)
	nuGetV2PackagePattern = regexp.MustCompile(`(?i)/package/([^/]+)/([^/]+)/?$`)
)

func parseNugetURL(urlPath string) (pkg string, ver string, success bool) {
	urlPath = strings.Split(urlPath, "?")[0]

	// Helper function to check if a string looks like a version
	isValidVersion := func(v string) bool {
		if len(v) == 0 {
			return false
		}
		// A simple check: version should start with a digit.
		// NuGet versions are typically Major.Minor.Patch[-Suffix].
		return v[0] >= '0' && v[0] <= '9'
	}

	matches := nuGetV3FlatPattern.FindStringSubmatch(urlPath)
	if len(matches) >= 3 {
		pkgName := strings.ToLower(matches[1])
		version := matches[2]
		if pkgName != "" && version != "" && isValidVersion(version) {
			return pkgName, version, true
		}
	}

	matches = nuGetV2PackagePattern.FindStringSubmatch(urlPath)
	if len(matches) >= 3 {
		pkgName := strings.ToLower(matches[1])
		version := matches[2]
		if pkgName != "" && version != "" && isValidVersion(version) {
			return pkgName, version, true
		}
	}

	parts := strings.Split(strings.Trim(urlPath, "/"), "/")
	if len(parts) >= 2 {
		for i := len(parts) - 2; i >= 0; i-- {
			potentialPkg := parts[i]
			potentialVer := parts[i+1]

			if len(potentialVer) > 0 && (potentialVer[0] >= '0' && potentialVer[0] <= '9') &&
				!(len(potentialPkg) > 0 && (potentialPkg[0] >= '0' && potentialPkg[0] <= '9')) {

				if i+2 < len(parts) {
					filename := strings.ToLower(parts[i+2])
					if strings.Contains(filename, strings.ToLower(potentialPkg)) && strings.Contains(filename, potentialVer) && (strings.HasSuffix(filename, ".nupkg") || strings.HasSuffix(filename, ".nuspec")) {
						return strings.ToLower(potentialPkg), potentialVer, true
					}
				} else {
					return strings.ToLower(potentialPkg), potentialVer, true
				}
			}
		}
	}

	return "", "", false
}

func Handle(p *policy.Policy, urlPath string, r *http.Request) *session.Activity {
	knownNuGetHosts := map[string]bool{
		"api.nuget.org":      true,
		"www.nuget.org":      true,
		"pkgs.dev.azure.com": true,
	}

	if _, ok := knownNuGetHosts[r.Host]; !ok {
		if !strings.Contains(strings.ToLower(r.URL.Path), "nuget") && !strings.Contains(strings.ToLower(r.Host), "nuget") {
			return session.NilActivity
		}
	}

	pkg, ver, success := parseNugetURL(r.URL.Path)

	if !success {
		return session.NilActivity
	}

	purl := fmt.Sprintf("pkg:%s/%s@%s", model.Nuget, pkg, ver)

	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.Nuget,
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