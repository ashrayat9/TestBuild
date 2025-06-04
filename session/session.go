package session

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v51/github"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/oauth2"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
)

type Decision = model.Decision

type Activity = model.Activity

var NilActivity = &Activity{}

type Session struct {
	Project    string
	Workflow   string
	Builder    string
	BuilderUrl string
	BuildUrl   string
	StartTime  time.Time
	// scm info
	Scm           string
	ScmOrigin     string
	ScmCommit     string
	ScmPrevCommit string
	ScmBranch     string

	// Additional fields related to VB Integration
	ScanID         string
	activities     []*model.Activity
	PackageNameMap map[string]string
	cl             *clog.CLog
}

var (
	baseLogger  = clog.NewCLog("base-session")
	authToken   string
	portal      string
	openaiToken string
)

func init() {
	authToken = os.Getenv("INVISIRISK_JWT_TOKEN")
	portal = os.Getenv("INVISIRISK_PORTAL")
	openaiToken = os.Getenv("OPENAI_AUTH_TOKEN")
}

func NewSession(r *http.Request) *Session {
	r.ParseForm()
	cl := clog.NewCLog(r.FormValue("project"))
	scm := r.PostFormValue("scm")
	branch := r.PostFormValue("scm_branch")
	if scm == "git" {
		parts := strings.SplitN(branch, "/", 2)
		if len(parts) > 1 && parts[0] == "origin" {
			branch = parts[1]
		}
	}
	project := r.PostFormValue("project")
	project = url.PathEscape(project)
	sess := &Session{
		Project:    project,
		ScanID:     r.PostFormValue("id"),
		Builder:    r.PostFormValue("builder"),
		BuildUrl:   r.PostFormValue("build_url"),
		BuilderUrl: r.PostFormValue("builder_url"),

		Scm:           r.PostFormValue("scm"),
		ScmCommit:     r.PostFormValue("scm_commit"),
		ScmOrigin:     r.PostFormValue("scm_origin"),
		ScmBranch:     branch,
		ScmPrevCommit: r.PostFormValue("scm_prev_commit"),
		Workflow:      r.PostFormValue("workflow"),

		PackageNameMap: make(map[string]string),
		cl:             cl,
		StartTime:      time.Now(),
	}

	cl.Infof("New Session %p %v, sess %v rip %v", sess, r.Form, r.FormValue("project"), r.RemoteAddr)

	return sess
}

func (s *Session) Add(act *model.Activity) {
	if act == NilActivity {
		return
	}
	s.cl.Infof("new activity %v", act)
	s.activities = append(s.activities, act)
}

func (s *Session) End(w http.ResponseWriter, r *http.Request) {
	status := model.Unknown

	if r != nil {
		r.ParseForm()
		s.cl.Infof("End Session %p %v", s, r.Form)
		// success, failed, or canceled
		switch strings.ToLower(r.FormValue("status")) {
		case "success":
			status = model.Success
		case "aborted":
			fallthrough
		case "canceled":
			status = model.Aborted
		case "failure":
			fallthrough
		case "failed":
			status = model.Fail
		}
	} else {
		s.cl.Errorf("End Session without request")

	}

	// send it to the server
	bs := model.Build{
		Id:         s.ScanID,
		Project:    s.Project + " - " + s.Workflow,
		Builder:    s.Builder,
		BuilderUrl: s.BuilderUrl,
		BuildUrl:   s.BuildUrl,
		Activity:   s.activities,
		Status:     status,
		StartTime:  s.StartTime,
		EndTime:    time.Now(),

		Scm:           s.Scm,
		ScmOrigin:     s.ScmOrigin,
		ScmCommit:     s.ScmCommit,
		ScmPrevCommit: s.ScmPrevCommit,
		ScmBranch:     s.ScmBranch,
	}

	s.cl.Infof("build activity summary...")

	defer func() {
		if r := recover(); r != nil {
			s.cl.Errorf("Panic in End function: %v", r)
			// debug.PrintStack()
		}
	}()

	for _, act := range s.activities {
		fmt.Printf("%v\n", act)
	}
	// if github post to it
	if s.Builder == "github" {
		s.githubLog(r.Context(), &bs)
	}
	data, _ := json.Marshal(bs)

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
	if portal == "" {
		s.cl.Infof("invisirisk portal not set - skip post")
		return
	}
	if authToken == "" {
		s.cl.Infof("invisirisk portal set, but no auth toke - skip post")
		return
	}

	s.cl.Infof("Post to portal %s", portal)
	endpoint := fmt.Sprintf("%s/ingestionapi/v1/proxy_data?api_key=%s", portal, authToken)
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	gzipWriter.Write(data)

	gzipWriter.Close()
	s.cl.Infof("Data sent to portal: %s", string(data))
	s.cl.Infof("Uncompressed data size: %d bytes", len(data))
	s.cl.Infof("Compressed data size: %d bytes", buf.Len())
	s.cl.Infof("Sending to portal %s", endpoint)

	req, err := http.NewRequest("POST", endpoint, &buf)
	if err != nil {
		s.cl.Errorf("error creating build request to the portal %s", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	// This is not required anymore
	//req.Header.Set("Authorization", "token "+authToken)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	transport := &http.Transport{
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   false,
	}

	s.cl.Infof("Sending results to the portal")
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 120}

	resp, err := client.Do(req)

	if err != nil {
		s.cl.Errorf("error sending build to the portal %s", err)
		return
	}
	defer resp.Body.Close()
	s.cl.Infof("server response code %v", resp.StatusCode)
	if resp.StatusCode > 299 {
		s.cl.Errorf("error response build from the portal %s %v", endpoint, err)
	}
	s.cl.Infof("server response code %v", resp.StatusCode)
	respData, _ := io.ReadAll(resp.Body)
	s.cl.Infof("server response %v %s", resp.StatusCode, respData)

}

func (s *Session) githubLog(ctx context.Context, bs *model.Build) {
	token := os.Getenv("GITHUB_TOKEN")
	cl := clog.FromCtx(ctx)
	if token == "" {
		cl.Errorf("no github auth token - skip")
		return
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)
	parts := strings.Split(s.Project, "%2F")
	owner := parts[0]
	repo := parts[1]

	var details string

	for _, act := range bs.Activity {
		title := string(act.Name) + " - " + act.Action
		var extraDetails string
		switch act.Name {
		case model.Web:
			dact := act.Activity.(model.WebActivity)
			u, err := url.Parse(dact.URL)
			if err == nil {
				title += " - " + u.Host
			} else {
				title += " - " + dact.URL
			}
			extraDetails = fmt.Sprintf("- URL: %v\n", dact.URL)
		case model.Git:
			dact := act.Activity.(model.GitActivity)
			title += " - " + dact.Repo
		case model.NPM:
			dact := act.Activity.(model.PackageActivity)
			title += " - " + dact.Package + "@" + dact.Version
			extraDetails = fmt.Sprintf("- Repository: %v\n", dact.Repo)
		case model.Pypi:
			dact := act.Activity.(model.PackageActivity)
			title += " - " + dact.Package + "@" + dact.Version
			extraDetails = fmt.Sprintf("- Repository: %v\n", dact.Repo)
		case model.Composer:
			dact := act.Activity.(model.PackageActivity)
			title += " - " + dact.Package + "@" + dact.Version
			extraDetails = fmt.Sprintf("- Repository: %v\n", dact.Repo)
		}
		color := ":white_check_mark:"
		switch act.AlertLevel {
		case model.AlertCritical:
			color = ":no_entry_sign:"
		case model.AlertError:
			color = ":x:"
		case model.AlertWarning:
			color = ":warning:"

		}
		msg := fmt.Sprintf("### %s %s \n", color, title)
		summary, err := s.Summary(ctx, title, act.Checks)
		if err == nil {
			msg += "#### OpenAI Summary\n"
			msg += summary
			msg += "\n"
		}
		msg += "#### Details\n"
		msg += extraDetails
		for _, ch := range act.Checks {
			msg += fmt.Sprintf("- %v: %v\n", ch.Name, ch.Details)
		}

		details += msg
	}
	title := fmt.Sprintf("%s - Network Activities by Invisirisk", s.Workflow)
	summary := `Network activities from build systems captured by build system.`

	output := github.CheckRunOutput{
		Title:   &title,
		Summary: &summary,
		Text:    &details,
	}
	conclusion := "success"

	opt := github.CreateCheckRunOptions{
		Name:       fmt.Sprintf("%s - Network Activities by InvisiRisk", s.Workflow),
		HeadSHA:    bs.ScmCommit,
		Conclusion: &conclusion,
		Output:     &output,
	}
	cl.Infof("creating github checks %v ", opt)
	_, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, opt)
	if err != nil {
		cl.Errorf("error creating checks %v", err)
	}
}

var (
	requestTemplate = `Summarize in less than 100 words the following activity, and any related risk from build system:
		{{.Title}} resulted in the following activities
		{{range .Checks}}
 			- {{.Name}}: {{.Details}}
		{{end}}
`
)

func (s *Session) Summary(ctx context.Context, title string, checks []model.TechCheck) (string, error) {
	cl := clog.FromCtx(ctx)

	if openaiToken == "" {
		return "", errors.New("no openai token")
	}
	client := openai.NewClient(openaiToken)

	buf := bytes.NewBuffer([]byte{})
	tmpl := template.New("request")
	tmpl = template.Must(tmpl.Parse(requestTemplate))
	err := tmpl.Execute(buf, map[string]interface{}{"Title": title, "Checks": checks})
	if err != nil {
		cl.Errorf("error executing template: %v", err)
	}

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT3Dot5Turbo,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: buf.String(),
				},
			},
		},
	)

	if err != nil {
		cl.Errorf("error making openai call %v", err)
		return "", err

	}
	return resp.Choices[0].Message.Content, nil
}

func (s *Session) Log() *clog.CLog {
	return s.cl
}

type Sessions struct {
	sessions        map[string]*Session
	pendingSessions map[string]*Session
	mutex           sync.Mutex
}

func NewSessions() *Sessions {
	return &Sessions{
		sessions:        make(map[string]*Session),
		pendingSessions: make(map[string]*Session),
	}
}

func (ss *Sessions) Add(addr string, s *Session) {
	ss.mutex.Lock()
	defer func() { ss.mutex.Unlock() }()
	if s, ok := ss.sessions[addr]; ok {
		ss.pendingSessions[s.BuildUrl] = s
	}
	ss.sessions[addr] = s
}

func (ss *Sessions) Find(addr string) (*Session, bool) {
	ss.mutex.Lock()
	defer func() { ss.mutex.Unlock() }()

	s, ok := ss.sessions[addr]
	return s, ok
}
func (ss *Sessions) FindFirst() (*Session, bool) {
    ss.mutex.Lock()
    defer ss.mutex.Unlock()

    for _, s := range ss.sessions {
        return s, true
    }
    return nil, false
}
func (ss *Sessions) popFirstSession() *Session {
	ss.mutex.Lock()
	defer func() { ss.mutex.Unlock() }()
	var session *Session
	for host, s := range ss.sessions {
		delete(ss.sessions, host)
		session=s
		break
	}
	for buildUrl := range ss.pendingSessions {
		delete(ss.pendingSessions, buildUrl)
		break
	}
	return session
}
func (ss *Sessions) findNextSessionForScan(scanId string) (*Session, bool) {
	ss.mutex.Lock()
	defer func() { ss.mutex.Unlock() }()

	for _, s := range ss.sessions {
		if s.ScanID == scanId {
			return s, true
		}
	}
	return nil, false
}

func (ss *Sessions) popSession(host,buildUrl string) *Session {
		ss.mutex.Lock()
		defer func() { ss.mutex.Unlock() }()		
		if sess, ok := ss.sessions[host]; ok {
			delete(ss.sessions, host)
			return sess
		} else {
			if sess, ok := ss.pendingSessions[buildUrl]; ok {
				delete(ss.pendingSessions, buildUrl)
				return sess
			}
		}
		return nil
}

func (ss *Sessions) End(w http.ResponseWriter, r *http.Request) {
    addr := r.RemoteAddr
    host, _, _ := net.SplitHostPort(addr)
    r.ParseForm()
    buildUrl := r.PostFormValue("build_url")
	var sess *Session
    // Pop the current session
	if os.Getenv("GLOBAL_SESSION") == "true" {
		sess=ss.popFirstSession()
		baseLogger.Infof("Popped first session %v as global session", sess)
	}else{
    sess = ss.popSession(host, buildUrl)
	}
    baseLogger.Infof("Found session %v", sess)
    baseLogger.Infof("Existing sessions %v", len(ss.sessions))

    if sess == nil {
        baseLogger.Errorf("ignoring %s from %v nothing in cache", r.URL, r.RemoteAddr)
        return
    }

    // Find all other sessions with the same ScanID
    type sessionKey struct {
        host     string
        buildUrl string
    }
    var keysToCheck []sessionKey
    
    // Collect keys from regular sessions
    for hostKey, session := range ss.sessions {
        if session.ScanID == sess.ScanID {
            keysToCheck = append(keysToCheck, sessionKey{host: hostKey, buildUrl: ""})
        }
    }
    
    // Collect keys from pending sessions
    for urlKey, session := range ss.pendingSessions {
        if session.ScanID == sess.ScanID {
            keysToCheck = append(keysToCheck, sessionKey{host: "", buildUrl: urlKey})
        }
    }
    
    // Pop each related session in a single loop
    var relatedSessions []*Session
    for _, key := range keysToCheck {
        relatedSession := ss.popSession(key.host, key.buildUrl)
        if relatedSession != nil {
            baseLogger.Infof("Found related session with ScanID %v from host %v, buildUrl %v", 
                relatedSession.ScanID, key.host, key.buildUrl)
            relatedSessions = append(relatedSessions, relatedSession)
        }
    }

    // Bind all activities from related sessions to the current session
    for _, relatedSession := range relatedSessions {
        baseLogger.Infof("Binding activities from session with ScanID %v to current session", relatedSession.ScanID)
        for _, activity := range relatedSession.activities {
			baseLogger.Infof("Binding activity %v", activity)
            sess.Add(activity)
        }
    }

    // End the current session with all the aggregated information
    sess.End(w, r)
}