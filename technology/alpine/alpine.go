package alpine

import (
	"fmt"
	"log"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

// AlpinePackage represents the components of an Alpine package
type AlpinePackage struct {
	Name    string
	Version string
	Release string
}

// Constants for common patterns and strings
const (
	apkExtension   = ".apk"
	apkIndexFile   = "APKINDEX.tar.gz"
	releasePattern = `-r\d+$`
)

// isApkFile checks if a filename is an Alpine package
func isApkFile(filename string) bool {
	return strings.HasSuffix(filename, apkExtension)
}

// isApkIndexFile checks if a filename is an Alpine index file
func isApkIndexFile(filename string) bool {
	return strings.HasSuffix(filename, apkIndexFile)
}

// parseRelease extracts the release segment (-rX) from a filename
func parseRelease(filename string) (string, string, bool) {
	re := regexp.MustCompile(releasePattern)
	releaseMatch := re.FindString(filename)
	
	if releaseMatch == "" {
		return filename, "", false
	}
	
	base := strings.TrimSuffix(filename, releaseMatch)
	return base, releaseMatch, true
}

// findVersionBoundary finds where the package name ends and version begins
// Returns the index of the last hyphen separating name from version, or -1 if not found
func findVersionBoundary(str string) int {
	segments := strings.Split(str, "-")
	if len(segments) < 2 {
		return -1
	}
	
	// Start from the end and find the first segment that looks like a version
	joinedSegments := ""
	for i := len(segments) - 1; i > 0; i-- {
		segment := segments[i]
		// Check if segment starts with a digit (typical for versions)
		if len(segment) > 0 && segment[0] >= '0' && segment[0] <= '9' {
			// Calculate the position of this segment's start in the original string
			joinedSegments = "-" + segment + joinedSegments
			return len(str) - len(joinedSegments)
		}
		joinedSegments = "-" + segment + joinedSegments
	}
	
	return -1
}

// isValidVersion checks if a version string follows acceptable patterns
func isValidVersion(version string) bool {
	if len(version) == 0 {
		return false
	}
	
	// Version should start with a digit
	if version[0] < '0' || version[0] > '9' {
		return false
	}
	
	// Common version patterns
	patterns := []string{
		`^\d+\.\d+`, // Standard: 1.2, 1.2.3
		`^\d{8}`,    // Date-based: 20240226
		`^\d+_`,     // With underscore: 12_git20220924
	}
	
	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, version)
		if matched {
			return true
		}
	}
	
	// If no specific pattern matches but starts with digits, it's probably valid
	digitPrefix := regexp.MustCompile(`^\d+`)
	return digitPrefix.MatchString(version)
}

// parse extracts package name and version from Alpine package URL paths
// Returns package name, version, and success flag
func parse(urlPath string) (string, string, bool) {
	// Extract filename from path
	filename := path.Base(urlPath)
	
	if !isApkFile(filename) {
		return "", "", false
	}
	
	// Remove extension
	nameWithVersion := strings.TrimSuffix(filename, apkExtension)
	
	// Primary parsing approach
	pkg, version, success := primaryParse(nameWithVersion)
	if success {
		return pkg, version, true
	}
	
	// Fallback parsing approach
	pkg, version, success = fallbackParse(nameWithVersion)
	if success {
		return pkg, version, true
	}
	
	// Log failure case for future improvement
	log.Printf("Failed to parse Alpine package: %s", filename)
	return "", "", false
}

// primaryParse attempts to parse using release identification first
func primaryParse(nameWithVersion string) (string, string, bool) {
	// Extract release segment
	baseFilename, release, hasRelease := parseRelease(nameWithVersion)
	if !hasRelease {
		return "", "", false
	}
	
	// Find version boundary
	versionIdx := findVersionBoundary(baseFilename)
	if versionIdx == -1 {
		return "", "", false
	}
	
	// Extract package name and version
	pkg := baseFilename[:versionIdx]
	verBase := baseFilename[versionIdx+1:]
	version := verBase + release
	
	// Validate
	if !isValidVersion(verBase) {
		return "", "", false
	}
	
	return pkg, version, true
}

// fallbackParse uses a more aggressive approach for edge cases
func fallbackParse(nameWithVersion string) (string, string, bool) {
	// Use a more aggressive regex pattern
	patterns := []string{
		// Pattern for clear version numbers: package-name-1.2.3-r0
		`^(.*)-(\d+\.\d+[^-]*)-r\d+$`,
		// Pattern for date-based versions: package-name-20240226-r0
		`^(.*)-(\d{6,8})-r\d+$`,
		// Last resort pattern: anything-ending-with-rX
		`^(.*)-([^-]+)-r\d+$`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(nameWithVersion)
		
		if len(matches) == 3 {
			versionPart := matches[2] + "-" + strings.Split(nameWithVersion, "-r")[1]
			if isValidVersion(matches[2]) {
				return matches[1], versionPart, true
			}
		}
	}
	
	return "", "", false
}

// Handle processes Alpine package URL paths
func Handle(p *policy.Policy, urlPath string, r *http.Request) *session.Activity {
	// Check if the request is from Alpine CDN
	if !strings.Contains(r.Host, "alpinelinux.org") {
		return session.NilActivity
	}
	filename := path.Base(urlPath)
	// Handle special cases
	if isApkIndexFile(filename) {
		return &session.Activity{
			ActivityHdr: model.ActivityHdr{
				Name:   "alpine",
				Action: "index",
			},
			Activity: model.WebActivity{
				URL: r.URL.String(),
			},
		}
	}
	pkg, ver, success := parse(urlPath)
	if !success {
		return session.NilActivity
	}
	
	purl := fmt.Sprintf("pkg:%s/%s@%s", model.Alpine, pkg, ver)
	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.Alpine,
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