package ca

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	ca := NewCA()
	_, err := ca.IssueCertificate("www1.google.com")
	require.NoError(t, err)
}
