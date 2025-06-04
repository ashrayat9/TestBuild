package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
	"inivisirisk.com/pse/session"
	"inivisirisk.com/pse/utils"
)

type Policy struct {
	opa PolicyDecider
}
type PolicyInput struct{
	IsResponseReady bool `json:"is_response_ready" default:"false"`
	Request RequestPolicyInput `json:"request"`
	Response ResponsePolicyInput `json:"response,omitempty"`
}

type RequestPolicyInput struct {
	Action  string      `json:"action"`
	Host    string      `json:"host"`
	Details interface{} `json:"details"`
	PackageRegistry    model.ActivityName      `json:"package_registry"`
	ApiKey  string      `json:"api_key"`
	AdditionalContext interface{} `json:"additional_context"`
}

type RequestMetadata struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
}

// ResponsePolicyInput holds response metadata for policy processing
type ResponsePolicyInput struct {
	StatusCode int            `json:"status_code"`
	Status     string         `json:"status"`
	Headers    http.Header    `json:"headers"`
	Request    RequestMetadata `json:"request"`
	MimeType  string		   `json:"mime_type"`
	Checksum string         `json:"checksum"`
	ContentLength float32 `json:"content_length"`
	FileSize int64 `json:"file_size"`
}
const (
	Allow = "allow"
	Deny  = "deny"
	Alert = "alert"
)
type policyCheck struct{
	Policy string
	Detail string
	Decision string
}
type Decision struct {
	Decision   string
	AlertLevel model.AlertLevel
	Detail     string
	PolicyChecks []policyCheck
}

var (
	DefaultDecision = Decision{
		Decision: Allow,
	}
)
var(
	leaksPath="./leaks.toml"
	leaksPathTest="../leaks.toml"
)
type PolicyDecider interface {
	Decision(ctx context.Context, options sdk.DecisionOptions) (*sdk.DecisionResult, error)
	Stop(ctx context.Context)
}

type NoopDecider struct {
}

func (NoopDecider) Decision(ctx context.Context, options sdk.DecisionOptions) (*sdk.DecisionResult, error) {

	return &sdk.DecisionResult{
		Result: map[string]interface{}{
			"result": "allow",
		},
	}, nil
}

func (NoopDecider) Stop(ctx context.Context) {

}

func renderPolicy(file string, token string, policyUrl string, policyLog bool) (io.Reader, error) {
	u, err := url.ParseRequestURI(policyUrl)
	if err != nil {
		return nil, fmt.Errorf("malformed policy url. error %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("scheme must be https")
	}
	if u.Path == "" {
		return nil, errors.New("no path elements")
	}
	fmt.Printf("%v", u)
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	cfg, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	idx := strings.LastIndex(policyUrl, "/")
	if idx == -1 {
		return nil, errors.New("invalid url")
	}
	baseUrl := policyUrl[:idx]
	bundle := policyUrl[idx:]

	data := struct {
		PolicyToken   string
		PolicyBaseUrl string
		PolicyBundle  string
		PolicyLog     bool
	}{token, baseUrl, bundle, policyLog}

	tmp := template.Must(template.New("cfg").Parse(string(cfg)))
	p := bytes.NewBuffer([]byte{})
	tmp.Execute(p, &data)
	return p, nil
}

func NewPolicy(config string) (*Policy, error) {
	ctx, _ := clog.WithCtx(context.TODO(), "policy")

	token:= utils.GetApiKey()
	policyUrl:=utils.GetPolicyUrl()

	policyLog := os.Getenv("POLICY_LOG") != ""
	r, err := renderPolicy(config, token, policyUrl, policyLog)
	if err != nil {
		return nil, err
	}

	return newPolicy(ctx, r)

}

func newPolicy(ctx context.Context, cfg io.Reader) (*Policy, error) {
	log := logging.New()
	const DEFAULT_TIMEOUT = 10 // seconds
	readyChan := make(chan struct{}, 1)

	// custom ready chain and context to throw errors if opa cannot instantiate new configuration in given time frame
	ctx, cancel := context.WithTimeout(ctx, DEFAULT_TIMEOUT*time.Second)
	defer cancel()
	opa, err := sdk.New(ctx, sdk.Options{
		Config: cfg,
		Ready:  readyChan,
		Logger: log,
		//ConsoleLogger: log,
	})
	if err != nil {
		return nil, err
	}

	select {
	case <-readyChan:
		return &Policy{
			opa: opa,
		}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout While starting OPA: %w", ctx.Err())
	}
}

func (policy *Policy) GetOpaDecision(ctx context.Context, input PolicyInput) (map[string]interface{}, error) {
	// Fetch Decisions From OPA and return the decision in a map
	const DECISION_PATH string = "combined"
	cl := clog.FromCtx(ctx)
	options := sdk.DecisionOptions{
		Path:  DECISION_PATH,
		Input: input,
	}

	result, err := policy.opa.Decision(ctx, options)
	if err != nil {
		var opaErr *sdk.Error
		if errors.As(err, &opaErr) {
			cl.Errorf("error making decision: %v", opaErr)
			return nil, fmt.Errorf("error making decision: %w", opaErr)
		}

		return nil, err
	}

	res, ok := result.Result.(map[string]interface{})
	if !ok {
		cl.Errorf("invalid result type %T", result.Result)
		return nil, fmt.Errorf("invalid result type %T", result.Result)
	}

	return res, nil
}
func (policy *Policy) PolicyDecision(ctx context.Context, result *map[string]interface{}) (Decision, error) {
	cl := clog.FromCtx(ctx)
	const DECISION_PATH string = "final_decision"
	policyDecisionByOpa, policyErr := policy.extractDecision(*result, DECISION_PATH)
	if policyErr != nil {
		cl.Errorf("error while extracting final decision: %v", policyErr)
		return DefaultDecision, policyErr
	}

	decision, ok := (*policyDecisionByOpa)["result"].(string)
	policy_checks:=convertToPolicyChecks((*policyDecisionByOpa)["policy_checks"])
	if len(policy_checks) > 0 {
		cl.Infof("policy checks: %v", policy_checks)
	}
	if !ok {
		cl.Errorf("error while converting result on policy: %v", (*policyDecisionByOpa)["result"])
		return DefaultDecision, fmt.Errorf("invalid result type for key final_decision, %T", (*policyDecisionByOpa)["result"])
	}

	details, _ := (*policyDecisionByOpa)["details"].(string)

	parts := strings.Split(decision, "/")
	switch parts[0] {
	case "allow", "deny":
		return Decision{
			Decision: parts[0],
			Detail:   details,
			PolicyChecks: policy_checks,
		}, nil
	case "alert":
		var alert model.AlertLevel
		if len(parts) > 1 {
			switch model.AlertLevel(parts[1]) {
			case model.AlertCritical, model.AlertError, model.AlertWarning, model.AlertNone:
				alert = model.AlertLevel(parts[1])
			default:
				cl.Errorf("unknown alert type decision %v", parts)
			}
		}
		return Decision{
			Decision:   parts[0],
			AlertLevel: alert,
			Detail:     details,
			PolicyChecks: policy_checks,
		}, nil
	}

	return DefaultDecision, nil
}
func convertToPolicyChecks(data interface{}) []policyCheck {
	items, ok := data.([]interface{})
	if !ok {
		log.Println("Invalid data format: expected []interface{}")
		return nil
	}

	var result []policyCheck

	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			log.Println("Skipping entry: not a map[string]interface{}")
			continue
		}

		pc := policyCheck{
			Policy:   toString(entry["policy"]),
			Detail:   toString(entry["details"]),
			Decision: toString(entry["result"]),
		}

		result = append(result, pc)
	}

	return result
}
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", v)
}

func (policy *Policy) SecretCheckDecision(ctx context.Context, act *session.Activity, result *map[string]interface{}, body io.ReadCloser) (Decision, error) {
	/*
		Secret Policy Evaluation

		Evaluate the secret policy to determine whether to check for secrets and the corresponding action to take if a secret is found.

		Final Secret Check Decision

		Derive the final secret check decision and return a Decision based on the outcome of the secret checks.

		Default Behavior

		If no secret-related policies are found in the policy configuration, the default action is to alert and return an Alert Decision.
	*/
	cl := clog.FromCtx(ctx)
	var defaultSecretCheckDecision = map[string]interface{}{"check": true, "result": "deny", "alert_level": model.AlertCritical}
	const DECISION_PATH string = "final_secret_decision"
	secret,err:=utils.NewSecrets(GetSecretsFilePath(),"request")
	if err != nil {
		cl.Errorf("error initializing secret: %v", err)
		return DefaultDecision, err
	}

	secretCheckPolicy, secretErr := policy.extractDecision(*result, DECISION_PATH)
	if secretErr != nil {
		cl.Errorf("error while extracting Final Secret Decision from Opa.Taking Default Secret Check Decision. ERROR:  %v", secretErr)
		secretCheckPolicy = &defaultSecretCheckDecision
	}
	parseDecisionAndLevel(secretCheckPolicy)

	ctx = context.WithValue(ctx, utils.SecretPolicyCtx, secretCheckPolicy)
	cl.Infof("secret check policy: %v", ctx.Value(utils.SecretPolicyCtx))

	if body != nil && act.Name == model.Web && (*secretCheckPolicy)["check"].(bool) {
		cl.Infof("performing secret Checks...")
		utils.ReaderChain(ctx, body, secret)
	}

	decisionMap := map[model.Decision]string{
		model.Allow: Allow,
		model.Deny:  Deny,
		model.Alert: Alert,
	}

	return Decision{
		Decision:   decisionMap[act.ActivityHdr.Decision],
		AlertLevel: act.AlertLevel,
		Detail:     buildDetails(act.ActivityHdr.Checks),
	}, nil
}

func buildDetails(checks []model.TechCheck) string {
	var detailsBuilder strings.Builder
	for _, check := range checks {
		detailsBuilder.WriteString(fmt.Sprintf("%s\n", check.Details))
	}
	return detailsBuilder.String()
}
func (policy *Policy) updateDecisionKey(final_decision *string, decision Decision) error {
	// set final decision deny if decision is deny
	// flag alertFound if decision is alert
	if decision.Decision == Deny || *final_decision == Deny {
		*final_decision = Deny
		return nil
	}
	if decision.Decision == Alert {
		*final_decision = Alert
	}
	return nil
}
func (policy *Policy) updateAlertLevel(alertLevel *model.AlertLevel, decision Decision) error {
	// change alertLevel reference if given decision alert level is greater than current
	if decision.Decision != Alert {
		return nil
	}
	if utils.AlertLt(*alertLevel, decision.AlertLevel) {
		*alertLevel = decision.AlertLevel
	}
	return nil
}
func (policy *Policy) updateDetails(details *string, decision Decision) error {
	// append details to the details reference variable
	if decision.Decision == Allow {
		return nil
	}
	*details += decision.Detail
	return nil

}
func (policy *Policy) updateChecks(final_policy_checks *[]policyCheck, decision Decision) error {
	// append details to the details reference variable
	for _,decision := range decision.PolicyChecks {
		*final_policy_checks = append(*final_policy_checks, decision)
	}
	return nil
}

func (policy *Policy) generateFinalDecision(decisions ...Decision) Decision {
	/*
		generateFinalDecision generates a final decision given a list of Decisions.
		It takes into account decisions with highest alert levels and combines all details.
	*/
	var (
		finalDecision     string           = Allow
		highestAlertLevel model.AlertLevel = model.AlertNone
		combinedDetails   string           = ""
		combinedChecks    []policyCheck
	)

	for _, decision := range decisions {
		// set final decision deny if deny else update alertFound on alert
		policy.updateDecisionKey(&finalDecision, decision)

		// updates highest alert level
		policy.updateAlertLevel(&highestAlertLevel, decision)

		// append all details
		policy.updateDetails(&combinedDetails, decision)
		policy.updateChecks(&combinedChecks, decision)
	}

	return Decision{
		Decision:   finalDecision,
		AlertLevel: highestAlertLevel,
		Detail:     combinedDetails,
		PolicyChecks: combinedChecks,
	}
}

func GetRequestInput(act *session.Activity,req *http.Request) RequestPolicyInput {
	apiKey:= utils.GetApiKey()
	additional_context:= get_additional_input_context()
	return RequestPolicyInput{
			Action:          act.Action,
			Host:            req.Host,
			Details:         act.Activity,
			PackageRegistry: act.Name,
			ApiKey:          apiKey,
			AdditionalContext: additional_context,
		}
}
func (policy *Policy) GetOpaAndPolicyDecision(ctx context.Context, input PolicyInput) (map[string]interface{}, Decision, error) {
// GetOpaAndPolicyDecision retrieves decisions from OPA and evaluates them against the policy. It returns the OPA decision, the sanitized policy decision, and any error encountered during the process.
// 
// Parameters:
//   ctx - The context for managing request-scoped values.
//   input - The input data for policy evaluation.
// 
// Returns:
//   A map representing the OPA decision, a Decision object representing the
//   sanitized policy decision, and an error if any occurred.
	cl := clog.FromCtx(ctx)
	
	opa_decision, err := policy.GetOpaDecision(ctx, input)
	if err != nil {
		cl.Errorf("error generating response from OPA %v", err)
		return nil,DefaultDecision, err
	}

	sanitizedPolicyDecision, err := policy.PolicyDecision(ctx, &opa_decision)
	if err != nil {
		cl.Errorf("got error while evaluating policy %v", err)
		return opa_decision,DefaultDecision, err
	}
	return opa_decision,sanitizedPolicyDecision, nil
}
func (policy *Policy) GetRequestDecision(ctx context.Context, act *session.Activity, request *http.Request) (Decision, error) {
	/*
		Generates OPA decision based on policies on request data and metadata and returns a Decision based on the outcome of the evaluation.
	*/
	cl := clog.FromCtx(ctx)
	input := PolicyInput{
		Request: GetRequestInput(act,request),
		IsResponseReady: false,
	}
	opa_decision,sanitizedPolicyDecision, err := policy.GetOpaAndPolicyDecision(ctx, input)
	if err != nil {
		cl.Errorf("error generating response from OPA %v", err)
		return DefaultDecision, err
	}

	_, err = policy.SecretCheckDecision(ctx, act, &opa_decision, request.Body)
	if err != nil {
		cl.Errorf("got error while evaluating secret check %v", err)
		return sanitizedPolicyDecision, err
	}

	return sanitizedPolicyDecision, nil
}

func (policy *Policy) extractDecision(result map[string]interface{}, key string) (*map[string]interface{}, error) {
	// it transforms opa result key of any interface{} to map[string]interface{} for easy access of decision

	if decision, ok := result[key].(map[string]interface{}); ok {
		return &decision, nil
	}
	return nil, fmt.Errorf("invalid result type for key %s", key)
}

func (policy *Policy) GetResponseDecision(ctx context.Context, act *session.Activity, body io.ReadCloser, policy_input *PolicyInput) (Decision, error) {
	cl:= clog.FromCtx(ctx)
	// Generates OPA decision based on policies on response data and metadata
	opa_decision,policy_decision,err:=policy.GetOpaAndPolicyDecision(ctx, *policy_input)
	if err != nil {
		cl.Errorf("error generating response from OPA %v", err)
	}
	_, err = policy.SecretCheckDecision(ctx, act, &opa_decision, body)
	if err != nil {
		cl.Errorf("got error while evaluating secret check %v", err)
		return policy_decision, err
	}
	return policy_decision, nil
}
func (policy *Policy) Stop(ctx context.Context) {
	policy.opa.Stop(ctx)
}


func parseDecisionAndLevel(secretCheckPolicy *map[string]interface{}) error {
	/*
		Helper function to parse decision and alert level
	*/
	result := (*secretCheckPolicy)["result"].(string)
	decisionAndLevel := strings.Split(result, "/")
	decision := decisionAndLevel[0]
	var alertLevel model.AlertLevel
	if len(decisionAndLevel) > 1 {
		alertLevel = model.AlertLevel(decisionAndLevel[1])
	} else if decision == Deny {
		alertLevel = model.AlertCritical
	} else {
		alertLevel = model.AlertNone
	}
	(*secretCheckPolicy)["result"] = decision
	(*secretCheckPolicy)["alert_level"] = alertLevel

	return nil
}

func get_license_check_url() string {
	licenseCheckURL, err := utils.GetEnv("INVISIRISK_PORTAL", "Missing Env variable for INVISIRISK_PORTAL")
	if err != nil {
		licenseCheckURL = ""
	}else{
		licenseCheckURL += "/registry/v1/is-permissive"
	}
	return licenseCheckURL
}
func get_additional_input_context() map[string]interface{} {
	// adds extra context to be sent to OPA Input
	additional_infos:= make(map[string]interface{})
	additional_infos["license_check_url"] = get_license_check_url()

	return additional_infos
}

func GetSecretsFilePath() string {
	//  test and actual run takes different relative path formats
	cl := clog.FromCtx(context.Background())
	var finalLeaksPath string
	leaksPathEnv := os.Getenv("LEAKS_FILE_PATH")
	if leaksPathEnv != "" {
		finalLeaksPath = leaksPathEnv
	} else if _, err := os.Stat(leaksPath); os.IsNotExist(err) {
		finalLeaksPath = leaksPathTest
	} else {
		finalLeaksPath = leaksPath
	}
	cl.Infof("finalLeaksPath %v", finalLeaksPath)
	return finalLeaksPath
}
