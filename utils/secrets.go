package utils

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type secret struct {
	cfg config.Config
	httpCycle string
}

func NewSecrets(cfgFile string, httpCycle string) (*secret, error) {
	var (
		vc  config.ViperConfig
		cfg config.Config
		err error
	)
	viper.SetConfigFile(cfgFile)
	if err = viper.ReadInConfig(); err != nil {
		return nil, err
	}

	if err = viper.Unmarshal(&vc); err != nil {
		return nil, err
	}
	if cfg, err = vc.Translate(); err != nil {
		return nil, err
	}
	return &secret{
		cfg: cfg,
		httpCycle: httpCycle,
	}, nil
}

func (s *secret) Handle(ctx context.Context, r io.Reader) error {
	_, cl := clog.WithCtx(ctx, "secret")
	on_secret_action, alert_level, err := getSecretCheckDecision(ctx)
	if err != nil {
		cl.Errorf("error getting secret check decision %v", err)
		on_secret_action = model.Deny
		alert_level = model.AlertCritical
	}
	findings, err := s.detectReader(r)
	translated_findings := s.translateRule(findings, alert_level)

	cl.Infof("secrets %v, error %v", translated_findings, err)
	updateDecisionBySecret(ctx, on_secret_action, len(translated_findings) > 0)
	if len(translated_findings) == 0 {
		// if no secrets found, add a tech check indicating this with alertLevel none
		appendCheck(ctx, model.TechCheck{
			Name:       "Allow",
			Score:      10,
			AlertLevel: model.AlertNone,
			Details:    "No secrets found in the " + s.httpCycle,
			Policy: "secret_check",
		})
		return nil
	}else{
		appendCheck(ctx, translated_findings...)
	}
	return nil
}
func (s *secret) detect(data []byte) []report.Finding {
	detector := detect.NewDetector(s.cfg)
	return detector.DetectBytes([]byte(data))
}
func (s *secret) detectReader(r io.Reader) ([]report.Finding, error) {
	detector := detect.NewDetector(s.cfg)
	findings, err := detector.DetectReader(r, 4096)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (s *secret) obscure(secret string) string {
	res := ""

	for i, s := range secret {
		if len(secret) < 8 {
			res += "X"
		}
		if i < 4 || s == '-' || i > len(secret)-2 {
			res += string(s)
		} else {
			res += "X"
		}
	}
	return res
}

func (s *secret) translateRule(findings []report.Finding, alertLevel model.AlertLevel) []model.TechCheck {
	checks := make([]model.TechCheck, 0)
	for _, f := range findings {
		found := false
		name := strings.Replace(f.Description, " ", "-", -1)
		for i, c := range checks {
			if c.Name == name {
				checks[i].Details += "secret value " + s.obscure(f.Secret) + ","
				found = true
			}
		}
		if !found {
			checks = append(checks, model.TechCheck{
				Name:       name,
				Score:      0,
				AlertLevel: alertLevel,
				Details:    "secret value " + s.obscure(f.Secret) + ",",
				Policy: "secret_check",
			})
		}
	}
	return checks
}

func getSecretCheckDecision(ctx context.Context) (model.Decision, model.AlertLevel, error) {
	secretPolicy := ctx.Value(SecretPolicyCtx)
	var secDecision model.Decision
	var alertLevel model.AlertLevel
	secPolicy, ok := secretPolicy.(*map[string]interface{})
	if ok {
		switch (*secPolicy)["result"] {
		case "allow":
			secDecision = model.Allow
		case "deny":
			secDecision = model.Deny
		case "alert":
			secDecision = model.Alert
		}
		alertLevel = (*secPolicy)["alert_level"].(model.AlertLevel)
	} else {
		return model.Allow, model.AlertNone, errors.New("no secret policy found")
	}
	return secDecision, alertLevel, nil
}
func updateDecisionBySecret(ctx context.Context, on_secret_action model.Decision, has_findings bool) {
	v := ctx.Value(ActCtxKey)
	act, ok := v.(*model.Activity)
	if !has_findings || !ok {
		return
	}

	if on_secret_action == model.Deny {
		act.Decision = model.Deny
	}
	if on_secret_action == model.Alert && act.Decision != model.Deny {
		act.Decision = model.Alert
	}
}
