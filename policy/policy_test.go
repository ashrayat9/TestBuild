package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/invisirisk/svcs/model"
	"github.com/joho/godotenv"
	sdktest "github.com/open-policy-agent/opa/sdk/test"
	"github.com/stretchr/testify/require"
	"inivisirisk.com/pse/session"
)

func TestPolicy(t *testing.T) {
	godotenv.Load("../.env")

	ctx := context.Background()
	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"git.rego": `
			package git
			import future.keywords.in

			repos_pull := ["github.com/lemurheavy/coveralls-public", "github.com/usirsiwal/godep"]
			repos_push := ["github.com/lemurheavy/coveralls-public", "github.com/usirsiwal/godep"]
			default decision = {"result": "allow","details":"No matching rules"}
			valid{
				input.request.details.repo in repos_pull
				input.request.action == "pull"
			}
			valid{
				input.request.details.repo in repos_push
				input.request.action == "push"
			}
			valid{
			input.request.package_registry!="git"
			}
			decision = {"result": "deny","details":"No matching rules"} {
				not valid
			}
			`,
		"web.rego": `
			package web

			import future.keywords.in

			default decision = {"result": "allow", "details":"No matching rules"}
			read_methods := ["HEAD", "GET", "OPTIONS"]
			decision = {"result": "deny", "details":"No matching rules"} {
				not read_allow
			}
			read_allow {
				input.request.action == "pull"
			}	
			read_allow {
				glob.match("https://*.invisirisk.com/", [], input.request.details.url)
				input.request.action in read_methods
			}
			`,
		"block_response.rego": `
			package block_response

			default decision = {"result": "allow", "details":"No matching rules"}
			decision = {"result": "deny", "details":"No matching rules"} {
				has_malware
			}
			has_malware {
				input.response.mime_type=="application/x-msdownload"
			}
			`,		
		"combined.rego":`
			package combined

			import future.keywords.in
			default decisions := []
			policies:=["git","web","block_response"]
			# Generate decisions dynamically based on policies array
			decisions := [decision |
				policy_name := policies[_]
				decision := {
					"policy": policy_name,
					"result": data[policy_name].decision.result,
					"details": data[policy_name].decision.details
				}
			]

			# Default to deny if no other rules match
			default final_decision := {"result": "deny", "details": "One or more policies denied access"}

			# If any policy denies, return deny with details from all denying policies
			final_decision := {"result": "deny", "details": deny_details} {
				count([d | d := decisions[_]; d.result == "deny"]) > 0
				deny_details := concat(", ", [sprintf("%s (%s)", [d.details, d.policy]) | d := decisions[_]; d.result == "deny"])
			}

			# If no denies but at least one warn, return warn with details from all warning policies
			final_decision := {"result": "alert/warn", "details": warn_details} {
				count([d | d := decisions[_]; d.result == "deny"]) == 0
				count([d | d := decisions[_]; d.result == "warn"]) > 0
				warn_details := concat(", ", [sprintf("%s (%s)", [d.details, d.policy]) | d := decisions[_]; d.result == "warn"])
			}

			# If all policies allow, return allow
			final_decision := {"result": "allow", "details": "All policies allowed access"} {
				all_allowed
			}

			# Helper rule to check if all policies allow access
			all_allowed {
				count([d | d := decisions[_]; d.result == "allow"]) == count(decisions)
			}

			# secrets final decision

			secret_decisions := [decision |
				policy_name := policies[_]
				decision := {
					"policy": policy_name,
					"result": data[policy_name].secret_decision.result,
					"check": data[policy_name].secret_decision.check
				}
			]

			default final_secret_decision := {"result": "deny", "check": false}

			final_secret_decision := {"result": "alert/warn", "check": any_check} {
				count([d | d := secret_decisions[_]; d.result == "deny"]) == 0
				count([d | d := secret_decisions[_]; d.result == "warn"]) > 0
				any_check := count([d | d := secret_decisions[_]; d.check == true]) > 0
			}

			final_secret_decision := {"result": "deny", "check": any_check} {
				count([d | d := secret_decisions[_]; d.result == "deny"]) > 0
				any_check := count([d | d := secret_decisions[_]; d.check == true]) > 0
			}

			final_secret_decision := {"result": "allow", "check": any_check} {
				all_secret_allowed
				any_check := count([d | d := secret_decisions[_]; d.check == true]) > 0
			}

			all_secret_allowed {
				count([d | d := secret_decisions[_]; d.result == "allow"]) == count(secret_decisions)
			}
			`,
	}))
	require.NoError(t, err)

	defer server.Stop()
	config := []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundles/bundle.tar.gz"
			}
		},
		"decision_logs": {
			"console": true
		}
	}`, server.URL()))
	var opa *Policy
	go func() {
		opa, err = newPolicy(ctx, bytes.NewReader(config))

	}()
	require.Eventually(t, func() bool { return opa != nil }, 5*time.Second, time.Second)
	require.NoError(t, err)

	defer opa.Stop(ctx)
	act := session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "git",
			Action: "pull",
		},
		Activity: model.GitActivity{
			Repo: "github.com/lemurheavy/coveralls-public",
		},
	}

	result, err := opa.GetRequestDecision(ctx, &act, &http.Request{})
	rsq_input:=GetRequestInput(&act, &http.Request{})
	policy_input := PolicyInput{
		Request: rsq_input,
		Response: ResponsePolicyInput{
			StatusCode: 200,
			Status:     "OK",
			Headers:    http.Header{},
			MimeType:	"application/x-msdownload",
			ContentLength: 0,
			FileSize: 0,
			Checksum:	"",
			Request: RequestMetadata{
				Method:  "GET",
				URL:     "https://github.com/lemurheavy/coveralls-public",
				Headers: http.Header{},
			},
		},
	}


	require.NoError(t, err)
	require.Equal(t, Allow, result.Decision)

	act = session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "git",
			Action: "pull",
		},
		Activity: model.GitActivity{
			Repo: "github.com/lemurheavy/coveralls-public-error",
		},
	}
	result, err = opa.GetRequestDecision(ctx, &act, &http.Request{})

	require.NoError(t, err)
	require.Equal(t, Deny, result.Decision)

	rsp_result, err := opa.GetResponseDecision(ctx, &act, io.NopCloser(bytes.NewReader([]byte(""))), &policy_input)
	require.NoError(t, err)
	require.Equal(t, Deny, rsp_result.Decision)
	wact := session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "web",
			Action: "HEAD",
		},
		Activity: model.WebActivity{
			URL: "https://www.google.com/",
		},
	}
	result, err = opa.GetRequestDecision(ctx, &wact, &http.Request{})

	require.NoError(t, err)
	require.Equal(t, Deny, result.Decision)
	wact = session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   "web",
			Action: "HEAD",
		},
		Activity: model.WebActivity{
			URL: "https://www.invisirisk.com/",
		},
	}
	result, err = opa.GetRequestDecision(ctx, &wact, &http.Request{})

	require.NoError(t, err)
	require.Equal(t, Allow, result.Decision)
}

func TestConfig(t *testing.T) {
	reader, err := renderPolicy("../production/policy.json", "tokkk", "https://www.google.com/", false)
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)

	fmt.Printf("%s", data)
}
