package pypi // Parse valid PyPI package URL with package name and version number
import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)
var url="https://files.pythonhosted.org/packages/d9/61/somepacakge-1.0.0-py3-none-any.whl"
// Parse valid PyPI package URL with package name and version number
func TestParseValidPyPIPackageURL(t *testing.T) {

    pkg, ver, ok := parse(url)

    assert.True(t, ok)
    assert.Equal(t, "somepacakge", pkg)
    assert.Equal(t, "1.0.0", ver)
}

    // Handle URL with less than 3 parts in filename
func TestParseInvalidShortFilename(t *testing.T) {
	url:= "https://files.pythonhosted.org/packages/sample-package.tar.gz"
    pkg, ver, ok := parse(url)

    assert.False(t, ok)
    assert.Empty(t, pkg)
    assert.Empty(t, ver)
}

    // Handle request from files.pythonhosted.org with valid package path
func TestHandleValidRequest(t *testing.T) {
    p := &policy.Policy{}
    req, err := http.NewRequest("GET", "http://files.pythonhosted.org", nil)
    if err != nil {
        t.Fatalf("Failed to create request: %v", err)
    }
    path := url
    activity := Handle(p, path, req)
    if activity == session.NilActivity {
        t.Errorf("Expected valid activity, got NilActivity")
    }
}

    // Generate correct PURL format for valid PyPI package


    // Successfully split package filename into name and version components
func TestParsePackageFilename(t *testing.T) {
    pkg, ver, ok := parse("/somepackage-1.0.0-py3-none-any.whl")
    if !ok {
        t.Errorf("Expected successful parse, got failure")
    }
    if pkg != "somepackage" || ver != "1.0.0" {
        t.Errorf("Expected package 'somepackage' and version '1.0.0', got package '%s' and version '%s'", pkg, ver)
    }
}

    // Correctly identify version number starting with digits 0-9
func TestParseIdentifyVersionNumber(t *testing.T) {
	url:= "https://files.pythonhosted.org/packages/d9/61/sample-package-1.0.0-py3-none-any.whl"
    pkg, ver, act := parse(url)
    if !act {
        t.Errorf("Expected true, got false")
    }
    if pkg != "sample-package" {
        t.Errorf("Expected 'sample-package', got %s", pkg)
    }
    if ver != "1.0.0" {
        t.Errorf("Expected '1.0.0', got %s", ver)
    }
}

    // Process package name containing multiple hyphens
func TestParsePackageNameWithHyphens(t *testing.T) {
    url := "https://files.pythonhosted.org/packages/sample-package-name-2.3.4-py3-none-any.whl"
    pkg, ver, act := parse(url)
    
    if !act {
        t.Errorf("Expected true, got false")
    }
    if pkg != "sample-package-name" {
        t.Errorf("Expected 'sample-package-name', got %s", pkg)
    }
    if ver != "2.3.4" {
        t.Errorf("Expected '2.3.4', got %s", ver)
    }
}

    // Handle URL with no version number component
func TestParseNoVersionNumber(t *testing.T) {
    url := "https://files.pythonhosted.org/packages/sample-package.tar.gz"
    _, _, act := parse(url)
    
    if act {
        t.Errorf("Expected false, got true")
    }
}
