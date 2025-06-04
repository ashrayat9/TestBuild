package main

import (
	"testing"

	"github.com/mssola/user_agent"
)

func TestUa(t *testing.T) {
	ua := user_agent.New("git/2.30.2")
	ua.Parse("git/2.30.2")
	println(ua.UA())
}
