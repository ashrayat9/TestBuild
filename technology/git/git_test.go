package git

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/invisirisk/svcs/model"
	"github.com/stretchr/testify/assert"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
)

// Path with 4 parts correctly identifies git pull action from git-upload-pack
func TestHandleGitPullFromUploadPack(t *testing.T) {
    // Arrange
    path := "repo/owner/name/git-upload-pack"
    req, err := http.NewRequest("GET", "http://example.com/"+path, nil)
    if err != nil {
        t.Fatal(err)
    }

    policy := &policy.Policy{}

    // Act
    activity := Handle(policy, path, req)

    // Assert
    if activity == nil {
        t.Fatal("Expected non-nil activity")
    }
    if activity.Name != model.Git {
        t.Errorf("Expected activity name %v, got %v", model.Git, activity.Name)
    }
    if activity.Action != "pull" {
        t.Errorf("Expected action 'pull', got %v", activity.Action)
    }
    gitActivity := activity.Activity.(model.GitActivity)
    expectedRepo := "example.com/owner/name"
    if gitActivity.Repo != expectedRepo {
        t.Errorf("Expected repo %v, got %v", expectedRepo, gitActivity.Repo)
    }
}

    // Path with less than 4 parts returns NilActivity
func TestHandleShortPathReturnsNilActivity(t *testing.T) {
    // Arrange
    path := "repo/owner"
    req, err := http.NewRequest("GET", "http://example.com/"+path, nil)
    if err != nil {
        t.Fatal(err)
    }

    policy := &policy.Policy{}

    // Act
    activity := Handle(policy, path, req)

    // Assert
    if activity != session.NilActivity {
        t.Errorf("Expected NilActivity, got %v", activity)
    }
}

    // Path with 4 parts correctly identifies git push action from git-receive-pack
func TestPathIdentifiesGitPushAction(t *testing.T) {
    p := &policy.Policy{}
    path := "/user/repo/git-receive-pack"
    r := &http.Request{
        Host: "example.com",
        URL: &url.URL{
            RawQuery: "",
        },
    }
    
    activity := Handle(p, path, r)
    
    if activity == session.NilActivity {
        t.Fatalf("Expected a valid activity, got NilActivity")
    }
    
    if activity.Action != "push" {
        t.Errorf("Expected action 'push', got %s", activity.Action)
    }
    act:= activity.Activity.(model.GitActivity)

    expectedRepo := "example.com/user/repo"
    if act.Repo != expectedRepo {
        t.Errorf("Expected repo %s, got %s", expectedRepo, act.Repo)
    }
}

    // Service query parameter correctly identifies git pull action
func TestServiceQueryIdentifiesGitPullAction(t *testing.T) {
    p := &policy.Policy{}
    path := "/user/repo/some-action"
    r := &http.Request{
        Host: "example.com",
        URL: &url.URL{
            RawQuery: "service=git-upload-pack",
        },
    }
    
    activity := Handle(p, path, r)
    
    if activity == session.NilActivity {
        t.Fatalf("Expected a valid activity, got NilActivity")
    }
    
    if activity.Action != "pull" {
        t.Errorf("Expected action 'pull', got %s", activity.Action)
    }
    act:= activity.Activity.(model.GitActivity)

    expectedRepo := "example.com/user/repo"
    if act.Repo != expectedRepo {
        t.Errorf("Expected repo %s, got %s", expectedRepo, act.Repo)
    }
}

    // Service query parameter correctly identifies git push action
func TestServiceQueryIdentifiesGitPushAction(t *testing.T) {
    p := &policy.Policy{}
    path := "/user/repo/some-action"
    r := &http.Request{
        Host: "example.com",
        URL: &url.URL{
            RawQuery: "service=git-receive-pack",
        },
    }
    
    activity := Handle(p, path, r)
    
    if activity == session.NilActivity {
        t.Fatalf("Expected a valid activity, got NilActivity")
    }
    
    if activity.Action != "push" {
        t.Errorf("Expected action 'push', got %s", activity.Action)
    }
    act:= activity.Activity.(model.GitActivity)
    expectedRepo := "example.com/user/repo"
    if act.Repo != expectedRepo {
        t.Errorf("Expected repo %s, got %s", expectedRepo, act.Repo)
    }
}

    // Returns Activity object with correct Name, Action and Repo fields


func TestReturnsCorrectActivityObject(t *testing.T) {
    p := &policy.Policy{}
    path := "/user/repo/git-upload-pack"
    req, _ := http.NewRequest("GET", "http://example.com?service=git-upload-pack", nil)

    activity := Handle(p, path, req)

    expectedActivity := &model.Activity{
        ActivityHdr: model.ActivityHdr{
            Name:   model.Git,
            Action: "pull",
        },
        Activity: model.GitActivity{
            Repo: "example.com/user/repo",
        },
    }

    assert.Equal(t, expectedActivity, activity)
}

func TestGitSuffixTrimmedFromRepoPath(t *testing.T) {
    p := &policy.Policy{}
    path := "/user/repo.git/git-upload-pack"
    req, _ := http.NewRequest("GET", "http://example.com?service=git-upload-pack", nil)

    activity := Handle(p, path, req)

    expectedRepo := "example.com/user/repo"

    assert.Equal(t, expectedRepo, activity.Activity.(model.GitActivity).Repo)
}
