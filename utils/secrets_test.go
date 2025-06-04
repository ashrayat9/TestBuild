package utils

import (
	"fmt"
	"testing"

	"github.com/invisirisk/svcs/model"
	"github.com/stretchr/testify/require"
)

var (
	data = `
	defghp_N4GLp6K2gwqWupGTRjz9P7AOth62XP5Ohli8
	ghp_N4GLp6K2gwqWupGTRjz9P7AOth62XP5OhliA
	AKIATB2LXL65ETAWXXXX
	`
)

func TestSecret(t *testing.T) {
	s, err := NewSecrets("../leaks.toml", "request")

	require.NoError(t, err)

	findings := s.detect([]byte(data))
	ch := s.translateRule(findings, model.AlertNone)
	fmt.Printf("%v\n", ch)
}
