package ruby

import (
	"net/http/httptest"
	"reflect"
	"testing"

	// Mock/Placeholder definitions - replace with actual imports if available
	// Assumes these types exist and NilActivity is nil for comparison.
	// You might need to import your actual model/session packages.
	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/session"
)

// --- Test Setup ---
// Define constants or use actual imports
const (
	testActivityName = model.RubyGems // Assuming model.RubyGems = "gem"
)

// Mock session.NilActivity if needed, assuming it's nil for comparison
var testNilActivity *session.Activity = nil // Assuming session.NilActivity is nil

// --- Tests for parse ---

func TestParseRubyGemsPath(t *testing.T) {
	// Define model.RubyGems if not imported globally
	// model.RubyGems = testActivityName // Uncomment if needed locally

	testCases := []struct {
		name           string
		path           string
		wantPackage    string
		wantVersion    string
		wantValid      bool
		expectedLogMsg string // Optional: Check for specific log messages if needed
	}{
		// --- Valid Cases ---
		{
			name:        "Standard Gem Path",
			path:        "/gems/rails-7.0.4.gem",
			wantPackage: "rails",
			wantVersion: "7.0.4",
			wantValid:   true,
		},
		{
			name:        "Standard Downloads Path",
			path:        "/downloads/rake-13.0.6.gem",
			wantPackage: "rake",
			wantVersion: "13.0.6",
			wantValid:   true,
		},
		{
			name:        "Gem with Platform Specifier",
			path:        "/gems/nokogiri-1.15.5-x86_64-linux.gem",
			wantPackage: "nokogiri",
			wantVersion: "1.15.5-x86_64-linux",
			wantValid:   true,
		},
		{
			name:        "Gem with Multiple Hyphens in Name",
			path:        "/gems/actionpack-action_caching-1.2.2.gem",
			wantPackage: "actionpack-action_caching",
			wantVersion: "1.2.2",
			wantValid:   true,
		},
		{
			name:        "Gem with Underscore in Name",
			path:        "/gems/gem_with_underscore-1.0.0.gem",
			wantPackage: "gem_with_underscore",
			wantVersion: "1.0.0",
			wantValid:   true,
		},
		{
			name:        "Pre-release Version",
			path:        "/downloads/my-gem-0.1.0.pre.gem",
			wantPackage: "my-gem",
			wantVersion: "0.1.0.pre",
			wantValid:   true,
		},
		{
			name:        "No leading slash",
			path:        "gems/another-gem-2.3.4.gem",
			wantPackage: "another-gem",
			wantVersion: "2.3.4",
			wantValid:   true,
		},
		{
			name:        "Deeper path",
			path:        "/some/proxy/prefix/gems/deep-gem-5.0.gem",
			wantPackage: "deep-gem",
			wantVersion: "5.0",
			wantValid:   true,
		},

		// --- Invalid Cases ---
		{
			name:      "Wrong Suffix",
			path:      "/gems/rails-7.0.4.tgz",
			wantValid: false,
		},
		{
			name:      "No Suffix",
			path:      "/gems/rails-7.0.4",
			wantValid: false,
		},
		{
			name:      "API Path (JSON)",
			path:      "/api/v1/gems/rails.json",
			wantValid: false,
		},
		{
			name:      "Gemspec Path",
			path:      "/quick/Marshal.4.8/rack-2.2.6.4.gemspec.rz",
			wantValid: false,
		},
		{
			name:      "Filename without Version Hyphen",
			path:      "/gems/packageonly.gem",
			wantValid: false,
		},
		{
			name:      "Filename is only suffix",
			path:      "/gems/.gem",
			wantValid: false,
		},
		{
			name:      "Empty Filename",
			path:      "/gems/",
			wantValid: false,
		},
		{
			name:      "Empty Path",
			path:      "",
			wantValid: false,
		},
		{
			name:      "Path is just slash",
			path:      "/",
			wantValid: false,
		},
		{
			name:      "Filename starts with hyphen",
			path:      "/gems/-start-hyphen-1.0.gem",
			wantValid: false, // Based on current parse logic rejecting this
		},
		{
			name:      "Filename ends with hyphen (no version)",
			path:      "/gems/no-version-.gem",
			wantValid: false,
		},
		{
			name:      "No package name",
			path:      "/gems/-1.0.gem",
			wantValid: false, // Based on current parse logic rejecting empty package name
		},
	}

	// If you want to check logs, you'd need to set up log capturing
	// For now, we focus on the return values

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, ver, valid := parse(tc.path)

			if valid != tc.wantValid {
				t.Errorf("parse(%q) valid = %v; want %v", tc.path, valid, tc.wantValid)
			}

			if valid { // Only check package and version if expected to be valid
				if pkg != tc.wantPackage {
					t.Errorf("parse(%q) package = %q; want %q", tc.path, pkg, tc.wantPackage)
				}
				if ver != tc.wantVersion {
					t.Errorf("parse(%q) version = %q; want %q", tc.path, ver, tc.wantVersion)
				}
			} else { // If invalid, ensure package and version are empty
				if pkg != "" {
					t.Errorf("parse(%q) package = %q; want empty string for invalid", tc.path, pkg)
				}
				if ver != "" {
					t.Errorf("parse(%q) version = %q; want empty string for invalid", tc.path, ver)
				}
			}
			// Add log checking logic here if needed
		})
	}
}

// --- Tests for Handle ---

func TestHandleRubyGemsRequest(t *testing.T) {
	// Define model.RubyGems if not imported globally
	// model.RubyGems = testActivityName // Uncomment if needed locally

	testCases := []struct {
		name         string
		path         string
		host         string
		wantActivity *session.Activity // Expected Activity, or nil if invalid
	}{
		{
			name: "Valid Standard Gem",
			path: "/gems/rails-7.0.4.gem",
			host: "rubygems.org",
			wantActivity: &session.Activity{
				ActivityHdr: model.ActivityHdr{Name: model.RubyGems, Action: "get"},
				Activity: model.PackageActivity{
					Repo:    "rubygems.org",
					Package: "rails",
					Version: "7.0.4",
					Purl:    "pkg:gem/rails@7.0.4",
				},
			},
		},
		{
			name: "Valid Gem with Platform Specifier",
			path: "/downloads/nokogiri-1.15.5-x86_64-linux.gem",
			host: "gems.example.com",
			wantActivity: &session.Activity{
				ActivityHdr: model.ActivityHdr{Name: model.RubyGems, Action: "get"},
				Activity: model.PackageActivity{
					Repo:    "gems.example.com",
					Package: "nokogiri",
					Version: "1.15.5-x86_64-linux",
					Purl:    "pkg:gem/nokogiri@1.15.5-x86_64-linux",
				},
			},
		},
		{
			name: "Valid Gem with Complex Name",
			path: "/gems/actionpack-action_caching-1.2.2.gem",
			host: "rubygems.org",
			wantActivity: &session.Activity{
				ActivityHdr: model.ActivityHdr{Name: testActivityName, Action: "get"},
				Activity: model.PackageActivity{
					Repo:    "rubygems.org",
					Package: "actionpack-action_caching",
					Version: "1.2.2",
					Purl:    "pkg:gem/actionpack-action_caching@1.2.2",
				},
			},
		},
		{
			name:         "Invalid Path - Wrong Suffix",
			path:         "/gems/rails-7.0.4.tgz",
			host:         "rubygems.org",
			wantActivity: testNilActivity, // Expecting NilActivity (nil)
		},
		{
			name:         "Invalid Path - No Version Hyphen",
			path:         "/gems/packageonly.gem",
			host:         "rubygems.org",
			wantActivity: testNilActivity, // Expecting NilActivity (nil)
		},
		{
			name:         "Invalid Path - API Call",
			path:         "/api/v1/gems/rails.json",
			host:         "rubygems.org",
			wantActivity: testNilActivity, // Expecting NilActivity (nil)
		},
		{
			name:         "Invalid Path - Empty Path",
			path:         "",
			host:         "rubygems.org",
			wantActivity: testNilActivity, // Expecting NilActivity (nil)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a simple mock HTTP request
			// Method and body are often irrelevant for path-based handlers like this
			req := httptest.NewRequest("GET", "http://"+tc.host+tc.path, nil)
			// If your handler *specifically* uses r.URL.Path instead of the passed 'path' string,
			// ensure the request URL is set correctly. The 'Handle' function signature
			// uses a separate 'path' argument, so we pass tc.path directly.

			// The Policy argument is not used in the provided Handle function, so pass nil
			gotActivity := Handle(nil, tc.path, req)

			// Use reflect.DeepEqual for robust comparison of structs (and nil)
			if !reflect.DeepEqual(gotActivity, tc.wantActivity) {
				t.Errorf("Handle(nil, %q, req[Host=%q]) = %+v; want %+v",
					tc.path, tc.host, gotActivity, tc.wantActivity)
			}
		})
	}
}