package nuget

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/invisirisk/svcs/model"
	"github.com/stretchr/testify/assert"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

func TestParseNugetURL(t *testing.T) {
	testCases := []struct {
		name        string
		urlPath     string
		expectedPkg string
		expectedVer string
		expectedOk  bool
	}{
		{
			name:        "NuGet v3 Flat Container Nupkg",
			urlPath:     "/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
			expectedPkg: "newtonsoft.json",
			expectedVer: "13.0.1",
			expectedOk:  true,
		},
		{
			name:        "NuGet v3 Flat Container Nuspec (Mixed Case)",
			urlPath:     "/v3/flatcontainer/Newtonsoft.Json/13.0.1/Newtonsoft.Json.13.0.1.nuspec",
			expectedPkg: "newtonsoft.json",
			expectedVer: "13.0.1",
			expectedOk:  true,
		},
		{
			name:        "NuGet v2 Package",
			urlPath:     "/api/v2/package/Moq/4.16.1",
			expectedPkg: "moq",
			expectedVer: "4.16.1",
			expectedOk:  true,
		},
		{
			name:        "NuGet v2 Package with Trailing Slash",
			urlPath:     "/api/v2/package/NUnit/3.13.2/",
			expectedPkg: "nunit",
			expectedVer: "3.13.2",
			expectedOk:  true,
		},
		{
			name:        "Azure DevOps Flat2",
			urlPath:     "/myorg/myproject/_packaging/MyFeed/nuget/v3/flat2/serilog/2.10.0/serilog.2.10.0.nupkg",
			expectedPkg: "serilog",
			expectedVer: "2.10.0",
			expectedOk:  true,
		},
		{
			name:        "Azure DevOps FlatContainer",
			urlPath:     "/myorg/myproject/_packaging/MyFeed/nuget/v3/flatcontainer/Serilog.Sinks.Console/4.0.0/serilog.sinks.console.4.0.0.nupkg",
			expectedPkg: "serilog.sinks.console",
			expectedVer: "4.0.0",
			expectedOk:  true,
		},
		{
			name:        "URL with Query Parameters",
			urlPath:     "/v3/flatcontainer/entityframework/6.4.4/entityframework.6.4.4.nupkg?sv=2020-08-04&ss=bfqt&srt=sco",
			expectedPkg: "entityframework",
			expectedVer: "6.4.4",
			expectedOk:  true,
		},
		{
			name:        "Fallback Simple Path Package Version File",
			urlPath:     "/some/artifactory/My.Custom.Package/1.2.3-beta4/My.Custom.Package.1.2.3-beta4.nupkg",
			expectedPkg: "my.custom.package",
			expectedVer: "1.2.3-beta4",
			expectedOk:  true,
		},
		{
			name:        "Fallback Direct Package Version File",
			urlPath:     "/My.Other.Package/3.2.1/My.Other.Package.3.2.1.nupkg",
			expectedPkg: "my.other.package",
			expectedVer: "3.2.1",
			expectedOk:  true,
		},
		{
			name:        "Fallback Package Version No File",
			urlPath:     "/my.package.id/1.0.0",
			expectedPkg: "my.package.id",
			expectedVer: "1.0.0",
			expectedOk:  true,
		},
		{
			name:        "Invalid - Not enough segments",
			urlPath:     "/mypackage.nupkg",
			expectedPkg: "",
			expectedVer: "",
			expectedOk:  false,
		},
		{
			name:        "Invalid - No version-like segment",
			urlPath:     "/mypackage/notavers/mypackage.notavers.nupkg",
			expectedPkg: "",
			expectedVer: "",
			expectedOk:  false,
		},
		{
			name:        "Invalid - Path with only version",
			urlPath:     "/1.2.3/1.2.3.nupkg",
			expectedPkg: "",
			expectedVer: "",
			expectedOk:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, ver, ok := parseNugetURL(tc.urlPath)
			assert.Equal(t, tc.expectedOk, ok)
			assert.Equal(t, tc.expectedPkg, pkg)
			assert.Equal(t, tc.expectedVer, ver)
		})
	}
}

func TestHandle(t *testing.T) {
	p := &policy.Policy{} // Mock policy, not used by current Handle logic for decision

	testCases := []struct {
		name          string
		host          string
		path          string
		expectActivity bool
		expectedPkg   string
		expectedVer   string
		expectedPurl  string
	}{
		{
			name:          "Known Host api.nuget.org - Valid Path",
			host:          "api.nuget.org",
			path:          "/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
			expectActivity: true,
			expectedPkg:   "newtonsoft.json",
			expectedVer:   "13.0.1",
			expectedPurl:  "pkg:nuget/newtonsoft.json@13.0.1",
		},
		{
			name:          "Known Host pkgs.dev.azure.com - Valid Path",
			host:          "pkgs.dev.azure.com",
			path:          "/myorg/_packaging/MyFeed/nuget/v3/flat2/another.pkg/1.0.0/another.pkg.1.0.0.nupkg",
			expectActivity: true,
			expectedPkg:   "another.pkg",
			expectedVer:   "1.0.0",
			expectedPurl:  "pkg:nuget/another.pkg@1.0.0",
		},
		{
			name:          "Unknown Host - Path contains 'nuget'",
			host:          "my.private-repo.com",
			path:          "/custom/nuget/feed/my.package/1.2.3/my.package.1.2.3.nupkg",
			expectActivity: true,
			expectedPkg:   "my.package",
			expectedVer:   "1.2.3",
			expectedPurl:  "pkg:nuget/my.package@1.2.3",
		},
		{
			name:          "Unknown Host - Host contains 'nuget'",
			host:          "nuget.internal.company.com",
			path:          "/packages/my.corp.pkg/2.0.0/my.corp.pkg.2.0.0.nupkg",
			expectActivity: true,
			expectedPkg:   "my.corp.pkg",
			expectedVer:   "2.0.0",
			expectedPurl:  "pkg:nuget/my.corp.pkg@2.0.0",
		},
		{
			name:          "Non-NuGet Host or Path",
			host:          "example.com",
			path:          "/some/other/file.zip",
			expectActivity: false,
		},
		{
			name:          "Known Host - Invalid NuGet Path",
			host:          "api.nuget.org",
			path:          "/v3/invalid/path",
			expectActivity: false,
		},
		{
			name:          "Known Host www.nuget.org - v2 package path",
			host:          "www.nuget.org",
			path:          "/api/v2/package/jQuery/3.6.0",
			expectActivity: true,
			expectedPkg:   "jquery",
			expectedVer:   "3.6.0",
			expectedPurl:  "pkg:nuget/jquery@3.6.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := &url.URL{Host: tc.host, Path: tc.path}
			req := &http.Request{Host: tc.host, URL: reqURL}

			activity := Handle(p, tc.path, req)

			if tc.expectActivity {
				assert.NotNil(t, activity, "Expected an activity, got nil")
				assert.NotEqual(t, session.NilActivity, activity, "Expected a valid activity, got NilActivity")
				assert.Equal(t, model.Nuget, activity.Name) // This will cause a compile error until model.Nuget is defined
				assert.Equal(t, "get", activity.Action)
				if pkgActivity, ok := activity.Activity.(model.PackageActivity); ok {
					assert.Equal(t, tc.host, pkgActivity.Repo)
					assert.Equal(t, tc.expectedPkg, pkgActivity.Package)
					assert.Equal(t, tc.expectedVer, pkgActivity.Version)
					assert.Equal(t, tc.expectedPurl, pkgActivity.Purl)
				} else {
					t.Errorf("Activity is not of type model.PackageActivity")
				}
			} else {
				assert.True(t, activity == session.NilActivity || activity == nil, "Expected NilActivity or nil")
			}
		})
	}
}
