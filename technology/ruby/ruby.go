package ruby

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

var (
	baseLog = clog.NewCLog("base-rubygems")
	// --- FIX 1: Use the standard PURL type "gem" consistently ---
	// This should align with PURL specs and test expectations.
	// If model.RubyGems should be "gem", ensure it's defined that way.
	// Forcing it here for clarity based on test failure.
	activityName = "gem"
)

// isValidRubyGemsPath remains the same
func isValidRubyGemsPath(gemPath string) bool {
	return strings.HasSuffix(gemPath, ".gem")
}

// parse function remains the same as the previously corrected version
func parse(gemPath string) (packageName, version string, valid bool) {
	if !isValidRubyGemsPath(gemPath) {
		baseLog.Infof("Invalid path: does not end with .gem: %s", gemPath)
		return "", "", false
	}

	parts := strings.Split(gemPath, "/")
	if len(parts) == 0 {
		baseLog.Infof("Invalid path: empty after split: %s", gemPath)
		return "", "", false
	}
	filename := parts[len(parts)-1]

	filenameBase := strings.TrimSuffix(filename, ".gem")
	if filenameBase == "" || filenameBase == "-" {
		baseLog.Infof("Invalid filename base: empty or just '-': %q", filenameBase)
		return "", "", false
	}

	splitIndex := -1
	for i := len(filenameBase) - 1; i > 0; i-- {
		if filenameBase[i-1] == '-' && unicode.IsDigit(rune(filenameBase[i])) {
			splitIndex = i - 1
			break
		}
	}

	if splitIndex == -1 {
		baseLog.Infof("Could not find version separator ('-digit') in: %s", filenameBase)
		return "", "", false
	}

	packageName = filenameBase[:splitIndex]
	version = filenameBase[splitIndex+1:]

	if packageName == "" || strings.HasPrefix(packageName, "-") {
		baseLog.Infof("Invalid package name extracted: %q from %s", packageName, filenameBase)
		return "", "", false
	}
	if version == "" {
		baseLog.Infof("Invalid version extracted (empty): from %s", filenameBase)
		return "", "", false
	}

	baseLog.Infof("Parsed RubyGems path: %s -> Package: %s, Version: %s", gemPath, packageName, version)
	return packageName, version, true
}

// Handle function updated for nil return
func Handle(p *policy.Policy, path string, r *http.Request) *session.Activity {
	pkg, ver, ok := parse(path)
	if !ok {
		// --- FIX 2: Return literal nil when parsing fails ---
		// This matches the test expectation of `<nil>` (a nil pointer).
		return nil
	}

	// Use the corrected activityName ("gem") for PURL
	purl := fmt.Sprintf("pkg:%s/%s@%s", activityName, pkg, ver)

	return &session.Activity{
		ActivityHdr: model.ActivityHdr{
			// Use the corrected activityName ("gem") for Name
			Name:   model.RubyGems,
			Action: "get",
			// Preserve other fields if they exist in your actual model.ActivityHdr
		},
		Activity: model.PackageActivity{
			Repo:    r.Host,
			Package: pkg,
			Version: ver,
			Purl:    purl,
			// Preserve other fields if they exist in your actual model.PackageActivity
		},
		// Preserve other fields if they exist in your actual session.Activity
	}
}