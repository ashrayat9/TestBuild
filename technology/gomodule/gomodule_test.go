package gomodule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoModule(t *testing.T) {
	pack, ver, act := parse("/github.com/kairoaraujo/goca/@v/v1.1.3.zip")
	assert.Equal(t, "github.com/kairoaraujo/goca", pack)
	assert.Equal(t, "v1.1.3", ver)
	assert.True(t, act)

	_, _, act = parse("github.com/kairoaraujo/goca/@v/v1.1.3.info")
	assert.False(t, act)
}
