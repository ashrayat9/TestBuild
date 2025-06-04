package npm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpm(t *testing.T) {
	s := "/color-space/-/color-space-1.16.0.tgz"
	pkg, rev, ok := parse(s)
	require.True(t, ok)
	assert.Equal(t, "color-space", pkg)
	assert.Equal(t, "1.16.0", rev)

}
func TestNPMCase2(t *testing.T) {
	s := "/@vitest/runner/-/runner-1.4.0.tgz"
	pkg, rev, ok := parse(s)
	require.True(t, ok)
	assert.Equal(t, "@vitest/runner", pkg)
	assert.Equal(t, "1.4.0", rev)
}
func TestNPMCase3(t *testing.T) {
	s := "/react-dom/-/react-dom-18.2.0.tgz"

	pkg, rev, ok := parse(s)
	require.True(t, ok)
	assert.Equal(t, "react-dom", pkg)
	assert.Equal(t, "18.2.0", rev)
}
func TestNPMCase4(t *testing.T) {
	s := "/@angular/core/-/@angular/core-17.3.0.tgz"
	pkg, rev, ok := parse(s)
	require.True(t, ok)
	assert.Equal(t, "@angular/core", pkg)
	assert.Equal(t, "17.3.0", rev)
}
func TestNPMCase5(t *testing.T) {
	s:="/@babel/helper-module-transforms/-/helper-module-transforms-7.23.3.tgz"
	pkg, rev, ok := parse(s)
	require.True(t, ok)
	assert.Equal(t, "@babel/helper-module-transforms", pkg)
	assert.Equal(t, "7.23.3", rev)
}

func TestNpmGithub(t *testing.T) {
	s := "/download/@invisirisk/ir-dep-npm/1.0.0/1f1419dafcb227111d4418c2e26c2322adaf8940"
	pkg, rev, ok := githubParse(s)
	require.True(t, ok)
	assert.Equal(t, "@invisirisk/ir-dep-npm", pkg)
	assert.Equal(t, "1.0.0", rev)
}
