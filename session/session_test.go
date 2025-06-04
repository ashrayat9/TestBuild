package session

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSeession(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.google.com/", nil)
	req.Form = url.Values{}
	req.Form.Add("project", "foo")
	NewSession(req)
}
