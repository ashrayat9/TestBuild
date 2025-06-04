package composer

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

// Handle request from repo.packagist.org with valid package path
func TestHandlePackagistRequestWithValidPath(t *testing.T) {
    // Setup
    req, err := http.NewRequest("GET", "https://repo.packagist.org/p/vendor/package.json", nil)
    if err != nil {
        t.Fatal(err)
    }

    policy := &policy.Policy{}
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }

    // Execute
    activity := Handle(policy, req, sess)

    // Verify
    assert.Equal(t, session.NilActivity, activity)
    assert.Equal(t, "vendor/package", sess.PackageNameMap["package"])
}

    // Handle request from unsupported hosts
func TestHandleUnsupportedHost(t *testing.T) {
    // Setup
    req, err := http.NewRequest("GET", "https://unsupported.host/some/path", nil)
    if err != nil {
        t.Fatal(err)
    }

    policy := &policy.Policy{}
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }

    // Execute
    activity := Handle(policy, req, sess)

    // Verify
    assert.Equal(t, session.NilActivity, activity)
    assert.Empty(t, sess.PackageNameMap)
}



    // Store sanitized package name in session PackageNameMap for packagist requests
func TestStoreSanitizedPackageNameInSession(t *testing.T) {
    p := &policy.Policy{}
    r := &http.Request{
        Host: "repo.packagist.org",
        URL:  &url.URL{Path: "/downloads/package/name"},
    }
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }
    
    Handle(p, r, sess)
    
    expectedPackageName := "name"
    if sess.PackageNameMap[expectedPackageName] != "package/name" {
        t.Errorf("Expected package name %v, got %v", "package/name", sess.PackageNameMap[expectedPackageName])
    }
}

    // Parse URL path with less than 3 parts
func TestParseURLPathWithLessThanThreeParts(t *testing.T) {
    urlPath := "/short/path"
    
    result := parse(urlPath)
    
    if result != "" {
        t.Errorf("Expected empty string, got %v", result)
    }
}

    // Handle empty URL path
func TestHandleEmptyURLPath(t *testing.T) {
    p := &policy.Policy{}
    r := &http.Request{
        Host: "repo.packagist.org",
        URL:  &url.URL{Path: ""},
    }
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }
    
    activity := Handle(p, r, sess)
    
    if activity != session.NilActivity {
        t.Errorf("Expected NilActivity, got %v", activity)
    }
}

    // Handle malformed package names in URL
func TestHandleMalformedPackageNames(t *testing.T) {
    p := &policy.Policy{}
    r := &http.Request{
        Host: "repo.packagist.org",
        URL:  &url.URL{Path: "/malformed/package/name"},
    }
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }
    
    activity := Handle(p, r, sess)
    
    if activity != session.NilActivity {
        t.Errorf("Expected NilActivity, got %v", activity)
    }
}

    // Handle request with empty host
func TestHandleRequestWithEmptyHost(t *testing.T) {
    p := &policy.Policy{}
    r := &http.Request{
        Host: "",
        URL:  &url.URL{Path: "/some/path"},
    }
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }
    
    activity := Handle(p, r, sess)
    
    if activity != session.NilActivity {
        t.Errorf("Expected NilActivity, got %v", activity)
    }
}

    // Handle nil policy, request or session parameters
func TestHandleNilParameters(t *testing.T) {
    var p *policy.Policy = nil
    var r *http.Request = nil
    sess := &session.Session{
        PackageNameMap: make(map[string]string),
    }
    activity := Handle(p, r, sess)
    
    if activity != session.NilActivity {
        t.Errorf("Expected NilActivity, got %v", activity)
    }
}
