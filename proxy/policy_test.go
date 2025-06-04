package proxy

import (
	"os"
	"testing"

	"github.com/gabriel-vasile/mimetype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inivisirisk.com/pse/config"
	"inivisirisk.com/pse/session"
	"inivisirisk.com/pse/technology/gomodule"
)

func TestMatchPath(t *testing.T) {
	cfg, err := config.Parse("../config/cfg.yaml")
	require.NoError(t, err)
	path, match := matchPath("repo.maven.apache.org/maven2/org/sonatype/sisu/sisu-inject-bean/1.4.2/sisu-inject-bean-1.4.2.jar", cfg.MavenRepos)
	assert.True(t, match)
	assert.Equal(t, "/org/sonatype/sisu/sisu-inject-bean/1.4.2/sisu-inject-bean-1.4.2.jar", path)
}

func TestPolicy(t *testing.T) {
	cfg, err := config.Parse("../config/cfg.yaml")
	require.NoError(t, err)
	path, match := matchPath("proxy.golang.org/google.golang.org/protobuf/@v/list", cfg.GoProxies)
	assert.True(t, match)
	m := PolicyHandler{}
	act := gomodule.Handle(m.p, path, nil)
	assert.Equal(t, act, session.NilActivity)
}

func TestContentType(t *testing.T) {
	f, _ := os.Open("./testdata/ssh-keychain.dylib")
	t.Setenv("INVISIRISK_PORTAL", "https://www.google.com/")
	t.Setenv("INVISIRISK_JWT_TOKEN", "test-test")
	defer f.Close()
	mt, err := mimetype.DetectReader(f)
	require.NoError(t, err)
	assert.Equal(t, mt.String(), "application/x-mach-binary")
}
