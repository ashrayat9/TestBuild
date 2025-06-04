package maven

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaven(t *testing.T) {
	pkg, rev, act := parse("/org/sonatype/sisu/sisu-inject-bean/1.4.2/sisu-inject-bean-1.4.2.jar")
	assert.Equal(t, "org.sonatype.sisu.sisu-inject-bean", pkg)
	assert.Equal(t, "1.4.2", rev)
	assert.True(t, act)
	_, _, act = parse("/org/")
	assert.False(t, act)

}
