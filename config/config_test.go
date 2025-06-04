package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	_, err := Parse("test.yaml")
	require.Error(t, err)
	_, err = Parse("main.go")
	require.Error(t, err)
	cfg, err := Parse("cfg.yaml")
	require.NoError(t, err)
	fmt.Printf("%v\n", cfg)
}
