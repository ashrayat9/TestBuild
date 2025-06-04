package alpine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	// Assuming these types are defined like this based on usage.
	// Replace with actual imports if available.
	"github.com/invisirisk/svcs/model"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

// --- Mocks/Stubs for external types (if not importing real packages) ---
// You might already have these defined or imported. If not, minimal
// versions based on usage in alpine.go are needed for compilation.

/*
// Example minimal definitions if real imports are unavailable:
package model
type ActivityHdr struct {
    Name   string
    Action string
}
type WebActivity struct {
    URL string
}
type PackageActivity struct {
    Repo    string
    Package string
    Version string
    Purl    string
}

package policy
type Policy struct{} // Placeholder

package session
type Activity struct {
    ActivityHdr model.ActivityHdr
    Activity    interface{} // Can be WebActivity or PackageActivity
}
var NilActivity *Activity = nil // Represents no activity detected
*/

// --- Test cases for parse ---

func TestParse(t *testing.T) {
	testCases := []struct {
		name     string
		urlPath  string
		wantPkg  string
		wantVer  string
		wantOk   bool
	}{
		{
			name:    "Standard APK",
			urlPath: "/x86_64/package-name-1.2.3-r0.apk",
			wantPkg: "package-name",
			wantVer: "1.2.3-r0",
			wantOk:  true,
		},
		{
			name:    "Standard APK",
			urlPath: "/alpine/v3.17/main/x86_64/ca-certificates-bundle-20240226-r0.apk",
			wantPkg: "ca-certificates-bundle",
			wantVer: "20240226-r0",
			wantOk:  true,
		},
		{
			name:    "Standard APK no dir",
			urlPath: "another-pkg-10.5.0-r1.apk",
			wantPkg: "another-pkg",
			wantVer: "10.5.0-r1",
			wantOk:  true,
		},
		{
			name:    "Alternative format APK",
			urlPath: "/main/g++-12.2.1_git20220924-r4.apk",
			wantPkg: "g++",
			wantVer: "12.2.1_git20220924-r4", // The second regex handles this
			wantOk:  true,
		},
		{
			name:    "Alternative format APK no dir",
			urlPath: "libfoo-0.1.0_alpha-r2.apk",
			wantPkg: "libfoo",
			wantVer: "0.1.0_alpha-r2",
			wantOk:  true,
		},
		{
			name:    "Not an APK file",
			urlPath: "/x86_64/package-name-1.2.3-r0.txt",
			wantPkg: "",
			wantVer: "",
			wantOk:  false,
		},
		{
			name:    "APK Index file",
			urlPath: "/x86_64/APKINDEX.tar.gz",
			wantPkg: "",
			wantVer: "",
			wantOk:  false, // parse function specifically ignores non-.apk
		},
		{
			name:    "Malformed name (no -r)",
			urlPath: "package-name-1.2.3.apk",
			wantPkg: "",
			wantVer: "",
			wantOk:  false,
		},
		{
			name:    "Malformed name (no version digits)",
			urlPath: "package-name-abc-rx.apk",
			wantPkg: "",
			wantVer: "",
			wantOk:  false,
		},
		{
			name:    "Empty path",
			urlPath: "",
			wantPkg: "",
			wantVer: "",
			wantOk:  false,
		},
		{
			name:    "Path is just extension",
			urlPath: ".apk",
			wantPkg: "",
			wantVer: "",
			wantOk:  false, // path.Base returns ".apk", TrimSuffix leaves "", regex fails
		},
		{
			name:    "Filename only, no version parts",
			urlPath: "package.apk",
			wantPkg: "",
			wantVer: "",
			wantOk:  false, // Fails regex match
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotPkg, gotVer, gotOk := parse(tc.urlPath)
			if gotPkg != tc.wantPkg || gotVer != tc.wantVer || gotOk != tc.wantOk {
				t.Errorf("parse(%q) = (%q, %q, %t), want (%q, %q, %t)",
					tc.urlPath, gotPkg, gotVer, gotOk, tc.wantPkg, tc.wantVer, tc.wantOk)
			}
		})
	}
}

// --- Test cases for Handle ---

func TestHandle(t *testing.T) {
	// Define expected activities reused across tests
	apkIndexActivity := &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "alpine",
			Action: "index",
		},
		Activity: model.WebActivity{
			URL: "https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/APKINDEX.tar.gz", // Example URL
		},
	}

	standardPkgActivity := &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "alpine",
			Action: "get",
		},
		Activity: model.PackageActivity{
			Repo:    "dl-cdn.alpinelinux.org",
			Package: "package-name",
			Version: "1.2.3-r0",
			Purl:    "pkg:alpine/package-name@1.2.3-r0",
		},
	}

	altPkgActivity := &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "alpine",
			Action: "get",
		},
		Activity: model.PackageActivity{
			Repo:    "dl-cdn.alpinelinux.org",
			Package: "g++",
			Version: "12.2.1_git20220924-r4",
			Purl:    "pkg:alpine/g++@12.2.1_git20220924-r4",
		},
	}
	samplePkgActivity := &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "alpine",
			Action: "get",
		},
		Activity: model.PackageActivity{
			Repo:    "dl-cdn.alpinelinux.org",
			Package: "ca-certificates-bundle",
			Version: "20240226-r0",
			Purl:    "pkg:alpine/ca-certificates-bundle@20240226-r0",
		},
	}

	testCases := []struct {
		name    string
		urlPath string
		host    string // Host for the mock request
		want    *session.Activity
	}{
		{
			name:"Non-Alpine Host - Standard Package",
			urlPath: "/alpine/v3.17/main/x86_64/ca-certificates-bundle-20240226-r0.apk",
			host: "dl-cdn.alpinelinux.org",
			want: samplePkgActivity, // Need to adjust URL in want if needed
		},
		{
			name:    "Non-Alpine Host",
			urlPath: "/some/package.apk",
			host:    "example.com",
			want:    session.NilActivity,
		},
		{
			name:    "Alpine Host - APK Index",
			urlPath: "/alpine/v3.18/main/x86_64/APKINDEX.tar.gz",
			host:    "dl-cdn.alpinelinux.org",
			want:    apkIndexActivity, // Need to adjust URL in want if needed
		},
		{
			name:    "Alpine Host - Standard Package",
			urlPath: "/alpine/v3.18/main/x86_64/package-name-1.2.3-r0.apk",
			host:    "dl-cdn.alpinelinux.org",
			want:    standardPkgActivity,
		},
		{
			name:    "Alpine Host - Alternative Package",
			urlPath: "/alpine/v3.18/main/x86_64/g++-12.2.1_git20220924-r4.apk",
			host:    "dl-cdn.alpinelinux.org",
			want:    altPkgActivity,
		},
		{
			name:    "Alpine Host - Malformed Package Path",
			urlPath: "/alpine/v3.18/main/x86_64/invalid-package.apk",
			host:    "dl-cdn.alpinelinux.org",
			want:    session.NilActivity, // parse returns false
		},
		{
			name:    "Alpine Host - Non-APK file",
			urlPath: "/alpine/v3.18/main/x86_64/some-other-file.txt",
			host:    "dl-cdn.alpinelinux.org",
			want:    session.NilActivity, // parse returns false
		},
		{
			name:    "Alpine Host - Empty Path",
			urlPath: "",
			host:    "dl-cdn.alpinelinux.org",
			want:    session.NilActivity, // parse returns false
		},
        {
			name:    "Alpine Host - Root Path",
			urlPath: "/",
			host:    "dl-cdn.alpinelinux.org",
			want:    session.NilActivity, // parse returns false
		},

	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock request
			// Note: The URL in the request needs to be absolute for r.URL.String() to work well.
			fullURL := fmt.Sprintf("https://%s%s", tc.host, tc.urlPath)
			req := httptest.NewRequest(http.MethodGet, fullURL, nil)
			// The httptest server sets the Host header automatically,
			// but we can also set it explicitly if needed, though r.Host reads from URL usually.
			// For this test, setting the host in the URL is sufficient as r.Host relies on it.
            // If the code strictly used req.Header.Get("Host"), we'd set that instead.
            // Let's assume r.Host works as intended from the URL.

			// If testing the specific APK Index URL generation:
			if tc.name == "Alpine Host - APK Index" {
				// Adjust the expected URL based on the input path and host
                expectedIndexActivity := *apkIndexActivity // Copy struct
                expectedIndexActivity.Activity = model.WebActivity{ URL: fullURL } // Update URL
				tc.want = &expectedIndexActivity
			}


			// Policy is unused in the tested code path, so pass nil
			var mockPolicy *policy.Policy = nil

			got := Handle(mockPolicy, tc.urlPath, req)

			// Use reflect.DeepEqual for comparing structs, handles pointers correctly
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Handle(%q, %q) = %+v, want %+v", tc.urlPath, tc.host, got, tc.want)
				// Log details if complex structs differ
				if got != nil && tc.want != nil {
					t.Logf("Got Hdr: %+v, Want Hdr: %+v", got.ActivityHdr, tc.want.ActivityHdr)
					t.Logf("Got Activity: %+v, Want Activity: %+v", got.Activity, tc.want.Activity)
				}
			}
		})
	}
}