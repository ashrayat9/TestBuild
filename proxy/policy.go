package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"

	"inivisirisk.com/pse/config"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/session"
	"inivisirisk.com/pse/technology/alpine"
	"inivisirisk.com/pse/technology/composer"
	"inivisirisk.com/pse/technology/git"
	"inivisirisk.com/pse/technology/gomodule"
	"inivisirisk.com/pse/technology/maven"
	"inivisirisk.com/pse/technology/npm"
	"inivisirisk.com/pse/technology/nuget"
	"inivisirisk.com/pse/technology/pypi"
	"inivisirisk.com/pse/technology/ruby"
	"inivisirisk.com/pse/utils"
)

type PolicyHandler struct {
	next http.Handler
	p    *policy.Policy
}

const (
	self = "pse.invisirisk.com"
)

var (
	sessions   = session.NewSessions()
	baseLogger = clog.NewCLog("base")
)

func (m *PolicyHandler) remoteIp(r *http.Request) string {
	addr := r.RemoteAddr
	host, _, _ := net.SplitHostPort(addr)
	return host
}

func (m *PolicyHandler) caCert(w http.ResponseWriter, r *http.Request) {
	cl := clog.FromCtx(r.Context())
	f, err := os.Open("/tmp/ca/invisirisk.com/ca/invisirisk.com.crt")
	if err != nil {
		cl.Errorf("CA certificate not available")
		w.WriteHeader(404)
		return
	}
	io.Copy(w, f)
}

func (m *PolicyHandler) PseEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/start":
		sess := session.NewSession(r)
		sessions.Add(m.remoteIp(r), sess)
	case "/end":
		sessions.End(w, r)
	case "/ca":
		m.caCert(w, r)
	}

}

func matchPath(path string, paths []string) (string, bool) {
	for _, p := range paths {
		if strings.Index(path, p) == 0 {
			return path[len(p):], true
		}
	}
	return "", false
}

func (m *PolicyHandler) handle(s string, cfg *config.Config, r *http.Request, sess *session.Session) *session.Activity {
	if strings.HasPrefix(r.UserAgent(), "Composer") {
		return composer.Handle(m.p, r, sess)
	}
	path, match := matchPath(s, cfg.GitRepos)
	if match {
		return git.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.GoProxies)
	if match {
		return gomodule.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.MavenRepos)
	if match {
		return maven.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.NpmRepos)
	if match {
		return npm.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.PypiRepos)
	if match {
		return pypi.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.AlpineRepos)
	if match {
		return alpine.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.RubygemsRepos)
	if match {
		return ruby.Handle(m.p, path, r)
	}
	path, match = matchPath(s, cfg.NugetRepos)
	if match {
		return nuget.Handle(m.p, path, r)
	}
	return nil
}


func (m *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var sess *session.Session
	var ok bool
	if os.Getenv("GLOBAL_SESSION") == "true" {
		baseLogger.Infof("Global session enabled")
		sess,ok = sessions.FindFirst()
	}else{
		sess, ok = sessions.Find(m.remoteIp(r))
	}
	if !ok {
		baseLogger.Errorf("request with session from %v", r.RemoteAddr)
	}

	cl := baseLogger
	if sess != nil {
		cl = sess.Log()
	}

	r.URL.Scheme = "https"
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	if r.Host == self {
		m.PseEndpoint(w, r)
		return
	}

	ctx, cl = clog.WithClog(ctx, cl, r.URL.Host)
	u := r.URL.String()
	cl.Infof("url %s Method %s", u, r.Method)

	cfg := config.Cfg()
	act := m.handle(r.URL.Host+r.URL.Path, cfg, r, sess)
	if act == nil || act == session.NilActivity {
		act = &session.Activity{
			ActivityHdr: model.ActivityHdr{
				Name:   model.Web,
				Action: r.Method,
			},
			Activity: model.WebActivity{
				URL: u,
			},
		}
	}
	act.Host= r.Host
	ctx = context.WithValue(ctx, utils.ActCtxKey, act)
	r = r.WithContext(ctx)

	if act != session.NilActivity {
		dec, err := m.p.GetRequestDecision(ctx, act, r)
		if err != nil {
			cl.Errorf("decision error %v", err)
			act.Decision = model.Alert
		}
		cl.Infof("decision %v", dec)
		
		BuildActivity(act, dec,false)

		if sess != nil {
			sess.Add(act)
		}
		if act.Decision == model.Deny {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	m.next.ServeHTTP(w, r)
}
func getOpaResponseInput(act *session.Activity, rsp_data *utils.ResponseData) policy.PolicyInput {
	rsp:=rsp_data.Response
	req:=policy.GetRequestInput(act,rsp_data.Response.Request)
	return policy.PolicyInput{
			IsResponseReady: true,
			Request: req,
			Response: policy.ResponsePolicyInput{
				StatusCode: rsp.StatusCode,
				Status:     http.StatusText(rsp.StatusCode),
				Headers:    rsp.Header,
				MimeType:	rsp_data.Mime,
				ContentLength: utils.StrToFloat(rsp.Header.Get("Content-Length")),
				FileSize: rsp_data.FileSizeByte,
				Checksum:	rsp_data.Checksum,
				Request: policy.RequestMetadata{
					Method:  rsp.Request.Method,
					URL:     rsp.Request.URL.String(),
					Headers: rsp.Request.Header,
				},
			},
		}
}
func  ModifyResponseBasedOnPolicy( p *policy.Policy, ctx context.Context, rsp_data *utils.ResponseData) error {

	// generate response metadata and calls GetResponseDecision to fetch OPA decision and binds it with activity
	cl := clog.FromCtx(ctx)
	v := ctx.Value(utils.ActCtxKey)
	act, ok := v.(*model.Activity)
	if !ok {
		cl.Errorf("invalid activity type %T", v)
	}
	policy_input := getOpaResponseInput(act,rsp_data)
	// generate OPA decisions for response
	response_decision,_:=p.GetResponseDecision(ctx, act, rsp_data.Response.Body, &policy_input)
	// bind the response decision with activity log
	BuildActivity(act, response_decision,true)

	// change status code based if deny
	if act.Decision == model.Deny {
		rsp_data.Response.StatusCode = http.StatusForbidden
	}
	return nil
}

func BuildActivity(act *model.Activity,dec policy.Decision, is_response_cycle bool) error {
	// binds the decision and checks to activity handler based on the OPA decision from request and response cycle

	if is_response_cycle {
		if dec.Decision == policy.Deny  {
			//  if current decision is deny then set decision to deny
			act.Decision = model.Deny
			act.AlertLevel = model.AlertCritical
		}else if dec.Decision == policy.Alert && act.Decision == model.Allow {
			// if current decision is alert and prev decision is allow set to alert
			act.Decision = model.Alert
			act.AlertLevel= dec.AlertLevel	
		}
		// else activity decision is not changed
	}else {
		switch dec.Decision {
		case policy.Allow:
			act.Decision = model.Allow
		case policy.Deny:
			act.Decision = model.Deny
			act.AlertLevel = model.AlertCritical
		case policy.Alert:
			act.Decision = model.Alert
			act.AlertLevel = dec.AlertLevel
		}
	}
	details := ""
	if dec.Detail != "" {
		details += ": " + dec.Detail
	}
	// adds generated at time for each activity at the end of response cycle
	act.GeneratedAt = time.Now().UTC()
	appendPolicyChecksToTechCheck(act,dec)
	return nil
}
func appendPolicyChecksToTechCheck(act *model.Activity, dec policy.Decision) {
	for _, check := range dec.PolicyChecks {
		var PolicyDecision string
		var alertLevel model.AlertLevel

		switch check.Decision {
		case policy.Allow:
			PolicyDecision = "Allow"
			alertLevel= model.AlertNone
		case policy.Deny:
			PolicyDecision = "Block"
			alertLevel= model.AlertCritical
		default:
			PolicyDecision = "Alert"
			alertLevel= model.AlertLevel(check.Decision)
		}

		act.Checks = append(act.Checks, model.TechCheck{
		Name:       PolicyDecision,
		AlertLevel: alertLevel,
		Details:    check.Detail,
		Policy:	check.Policy,
		Score:      alertScore(alertLevel),
	})
}}

func alertScore(alert model.AlertLevel) float64 {
	switch alert {
	case model.AlertWarning:
		return 5
	case model.AlertError:
		return 3
	case model.AlertCritical:
		return 0
	}
	return 10
}
