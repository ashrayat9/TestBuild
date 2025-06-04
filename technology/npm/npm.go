package npm

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

var (
	baseLog = clog.NewCLog("base-npm")
)

// /download/@invisirisk/ir-dep-npm/1.0.0/1f1419dafcb227111d4418c2e26c2322adaf8940
func githubParse(url string) (string, string, bool) {
	parts := strings.Split(url, "/")
	if len(parts) < 5 {
		return "", "", false
	}
	if parts[1] != "download" {
		return "", "", false
	}
	scope := parts[2]
	pkg := parts[3]
	ver := parts[4]
	return scope + "/" + pkg, ver, true

}
// isValidNPMURL checks if the URL is a valid NPM package URL
func isValidNPMURL(npmPath string) bool {
	return strings.HasSuffix(npmPath, ".tgz")
}

// extractVersionFromFilename extracts the version from the filename part of the URL
func extractVersionFromFilename(filename string) (version string, valid bool) {
	splitIndex := strings.LastIndex(filename, "-")
	if splitIndex == -1 {
		return "", false
	}
	return filename[splitIndex+1:], true
}

// isScopedPackage checks if the URL is for a scoped package (starts with @)
func isScopedPackage(pathParts []string) bool {
	return len(pathParts) >= 1 && strings.HasPrefix(pathParts[0], "@")
}

// extractPackageNameFromDashSegment extracts package name from path parts before the dash segment
func extractPackageNameFromDashSegment(pathParts []string) (packageName string, found bool) {
	dashIndex := -1
	for i, part := range pathParts {
		if part == "-" {
			dashIndex = i
			break
		}
	}
	
	if dashIndex != -1 && dashIndex > 0 {
		// Extract scope from path parts (parts before the "-" segment)
		scopeParts := pathParts[:dashIndex]
		packageName = strings.Join(scopeParts, "/")
		return packageName, true
	}
	
	return "", false
}

// extractPackageNameFromScopedURL handles extraction for scoped packages with various URL patterns
func extractPackageNameFromScopedURL(pathParts []string, filename string, splitIndex int) string {
	// First try to extract from path parts before the dash segment
	packageName, found := extractPackageNameFromDashSegment(pathParts)
	if found {
		return packageName
	}
	
	// For paths without a clear dash segment or with special formats like:
	// /@vitest/runner/-/runner-1.4.0.tgz
	
	// Try to extract scope and name from direct path parts
	if len(pathParts) >= 2 {
		scope := pathParts[0]
		name := pathParts[1]
		
		// Simplest case: @scope/name
		if strings.HasPrefix(scope, "@") && name != "-" {
			return scope + "/" + name
		}
	}
	
	// Try to extract from filename
	filenameBase := filename[:splitIndex]
	
	// Check if filename starts with @ (indicating scoped package in filename)
	if strings.HasPrefix(filenameBase, "@") {
		parts := strings.Split(filenameBase, "-")
		if len(parts) >= 2 {
			// Format: @scope-name-version.tgz → @scope/name
			return parts[0] + "/" + parts[1]
		}
		return filenameBase
	}
	
	// For formats like runner-1.4.0.tgz with a scope in the path
	if len(pathParts) > 0 && strings.HasPrefix(pathParts[0], "@") {
		// Extract scope from path
		scope := pathParts[0]
		return scope + "/" + filenameBase
	}
	
	// Non-scoped fallback
	return filenameBase
}

// extractPackageNameFromNonScopedURL handles extraction for non-scoped packages
func extractPackageNameFromNonScopedURL(filename string, splitIndex int) string {
	return filename[:splitIndex]
}

// parse parses an NPM URL path and extracts the package name and version
func parse(npmPath string) (packageName, version string, valid bool) {
	// Check if this is a valid NPM URL
	if !isValidNPMURL(npmPath) {
		return "", "", false
	}
	
	// Remove leading slash if present
	if strings.HasPrefix(npmPath, "/") {
		npmPath = npmPath[1:]
	}
	
	// Split path into parts
	pathParts := strings.Split(npmPath, "/")
	if len(pathParts) < 2 {
		return "", "", false
	}
	
	baseLog.Infof("Parsing NPM URL path: %v", npmPath)
	
	// Extract filename and trim extension
	filename := strings.TrimSuffix(pathParts[len(pathParts)-1], ".tgz")
	
	// Extract version from filename
	splitIndex := strings.LastIndex(filename, "-")
	if splitIndex == -1 {
		return "", "", false
	}
	
	version = filename[splitIndex+1:]
	
	// Extract package name based on whether it's a scoped package or not
	if isScopedPackage(pathParts) {
		packageName = extractPackageNameFromScopedURL(pathParts, filename, splitIndex)
	} else {
		packageName = extractPackageNameFromNonScopedURL(filename, splitIndex)
	}
	
	return packageName, version, true
}

func Handle(p *policy.Policy, path string, r *http.Request) *session.Activity {
	var pkg, ver string
	var act bool
	if r.Host == "npm.pkg.github.com" {
		pkg, ver, act = githubParse(path)
	} else {
		pkg, ver, act = parse(path)
	}
	if !act {
		return session.NilActivity
	}
	purl := fmt.Sprintf("pkg:%s/%s@%s", model.NPM, pkg, ver)
	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.NPM,
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
