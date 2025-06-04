package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Server starts successfully on specified port and serves files from given policy directory
func TestStartServerSuccessfully(t *testing.T) {
    tempDir := t.TempDir()
    TEST_PORT:=8081
    // Start server on port 0 (system assigns a free port)
    server := StartServer(TEST_PORT, tempDir)
    defer server.Close()
    var rsp *http.Response
    var err error
    require.Eventually(t, func() bool {
        rsp, err = http.Get(fmt.Sprintf("http://localhost:%d/test.txt", TEST_PORT))
        return err == nil
    }, 3*time.Second, 100*time.Millisecond, "server did not start in time")
    require.NoError(t, err, "failed to connect to server")
    require.Equal(t, http.StatusNotFound, rsp.StatusCode, "expected 404 response")
}


    // Starting server with invalid port number
func TestStartServerInvalidPort(t *testing.T) {
    port := -1
    tempDir := t.TempDir()

    server := StartServer(port, tempDir)
    defer server.Close()

    _, err := http.Get(fmt.Sprintf("http://localhost:%d/test.txt", port))
    require.Error(t, err)
}
