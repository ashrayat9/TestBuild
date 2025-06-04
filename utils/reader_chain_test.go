package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/invisirisk/svcs/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inivisirisk.com/pse/session"
)

func TestReaderChainForTransformer(t *testing.T) {

	r2, _ := os.Open("testdata/test.zip")
	defer func() {
		_ = r2.Close()
	}()
	data, _ := io.ReadAll(r2)

	r, err := os.Open("testdata/test.zip")
	defer func() {
		_ = r.Close()
	}()
	require.NoError(t, err)
	dm := &MimeChain{}
	sc := &Checksum{}
	fs:= &FileSize{}
	act := &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.Web,
			Action: "GET",
		},
		Activity: model.WebActivity{
			URL: "https://registry.npmjs.org/typescript/-/typescript-4.3.5.tgz",
		},
	}
	ctx:=context.WithValue(context.Background(), ActCtxKey, act)
	top := ReaderChain(ctx, r, dm, sc,fs)
	d, err := io.ReadAll(top)
	require.NoError(t, err)
	assert.Equal(t, data, d)
	assert.Equal(t, "application/zip", dm.Mime)
	assert.Equal(t, "b9a726efb1cd38178b5832ed6619a804", sc.Checksum)
	assert.Equal(t, int64(52457), fs.ByteSize)
}

func TestReaderChainForTypescript(t *testing.T) {
	r, err := os.Open("testdata/typescript.tgz")
	defer func() {
		_ = r.Close()
	}()
	require.NoError(t, err)
	dm := &MimeChain{}
	sc := &Checksum{}
	fs:= &FileSize{}
	act := &session.Activity{
			ActivityHdr: model.ActivityHdr{
				Name:   model.Web,
				Action: "GET",
			},
			Activity: model.WebActivity{
				URL: "https://registry.npmjs.org/typescript/-/typescript-4.3.5.tgz",
			},
		}
	ctx:=context.WithValue(context.Background(), ActCtxKey, act)
	top := ReaderChain(ctx, r, dm, sc,fs)
	io.ReadAll(top)
	require.NoError(t, err)
	assert.Equal(t, "application/gzip", dm.Mime)
	assert.Equal(t, "8fda1e008b1c018217b05a5dfd18e8c4", sc.Checksum)
	assert.Equal(t, int64(9581106), fs.ByteSize)
}
func TestReaderChainForBlankFile(t *testing.T) {
	r, err := os.Open("testdata/blank_test.txt")
	defer func() {
		_ = r.Close()
	}()
	require.NoError(t, err)
	dm := &MimeChain{}
	sc := &Checksum{}
	fs:= &FileSize{}
	act := &session.Activity{
			ActivityHdr: model.ActivityHdr{
				Name:   model.Web,
				Action: "GET",
			},
			Activity: model.WebActivity{
				URL: "https://registry.npmjs.org/typescript/-/typescript-4.3.5.tgz",
			},
		}
	ctx:=context.WithValue(context.Background(), ActCtxKey, act)
	top := ReaderChain(ctx, r, dm, sc,fs)
	io.ReadAll(top)
	require.NoError(t, err)
	assert.Equal(t, "text/plain", dm.Mime)
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", sc.Checksum)
	assert.Equal(t, int64(0), fs.ByteSize)
}
func TestActivityLogUpdate(t *testing.T) {
	r, err := os.Open("testdata/typescript.tgz")
	defer func() {
		_ = r.Close()
	}()
	require.NoError(t, err)
	
	dm := &MimeChain{Direction: "response"}
	sc := &Checksum{Direction: "response"}
	fs := &FileSize{Direction: "response"}
	act := &session.Activity{
		ActivityHdr: model.ActivityHdr{
			Name:   model.Web,
			Action: "GET",
		},
		Activity: model.WebActivity{
			URL: "https://registry.npmjs.org/typescript/-/typescript-4.3.5.tgz",
		},
	}

	ctx := context.WithValue(context.Background(), ActCtxKey, act)
	top := ReaderChain(ctx, r, dm, sc, fs)
	_, err = io.ReadAll(top)
	require.NoError(t, err)

	// Test asserts for tech checks in activity
	techChecks := act.Checks
	require.NotNil(t, techChecks)
	require.Len(t, techChecks, 3)

	assert.Contains(t, techChecks, model.TechCheck{
		Name:    "response-Type",
		Score:   10,
		Details: "mime: application/gzip",
	})

	assert.Contains(t, techChecks, model.TechCheck{
		Name:    "response-Checksum",
		Score:   10,
		Details: "checksum 8fda1e008b1c018217b05a5dfd18e8c4",
	})

	assert.Contains(t, techChecks, model.TechCheck{
		Name:    "File-Size",
		Score:   10,
		Details: "file size 9581106 bytes",
	})
}

func TestFoo(t *testing.T) {
	var v interface{} = &model.Activity{}

	if _, ok := v.(*model.Activity); ok {
		fmt.Printf("good\n")
	} else {
		fmt.Printf("bad")
	}
}

func TestConcurrentReaderChain(t *testing.T) {
 // Number of concurrent goroutines
 const numGoroutines = 10
 
 // Test files and their expected checksums
 testFiles := map[string]string{
  "testdata/test.zip":      "b9a726efb1cd38178b5832ed6619a804",
  "testdata/typescript.tgz": "8fda1e008b1c018217b05a5dfd18e8c4",
 }

 var wg sync.WaitGroup
 errors := make(chan error, numGoroutines*len(testFiles))
 
 // Run concurrent tests for each file
 for fileName, expectedChecksum := range testFiles {
  for i := 0; i < numGoroutines; i++ {
   wg.Add(1)
   go func(filename, expected string, routineNum int) {
    defer wg.Done()

    // Open the test file
    r, err := os.Open(filename)
    if err != nil {
     errors <- fmt.Errorf("routine %d: failed to open file %s: %v", routineNum, filename, err)
     return
    }
    defer r.Close()

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ctx=context.WithValue(ctx, ActCtxKey, &session.Activity{})
    defer cancel()

    // Create chains
    mimeChain := &MimeChain{Direction: "response"}
    checksumChain := &Checksum{Direction: "response"}
    sizeChain := &FileSize{Direction: "response"}

    // Create and process the chain
    reader := ReaderChain(ctx, r, mimeChain, checksumChain, sizeChain)
    
    // Read all data
    data, err := io.ReadAll(reader)
    if err != nil {
     errors <- fmt.Errorf("routine %d: failed to read data: %v", routineNum, err)
     return
    }

    // Verify data integrity
    if len(data) == 0 {
     errors <- fmt.Errorf("routine %d: no data read", routineNum)
     return
    }

    // Verify checksum
    if checksumChain.Checksum != expected {
     errors <- fmt.Errorf("routine %d: checksum mismatch - got %s, want %s", 
      routineNum, checksumChain.Checksum, expected)
     return
    }

    // Verify MIME type is not empty
    if mimeChain.Mime == "" {
     errors <- fmt.Errorf("routine %d: empty MIME type", routineNum)
     return
    }

    // Verify file size is positive
    if sizeChain.ByteSize <= 0 {
     errors <- fmt.Errorf("routine %d: invalid file size %d", routineNum, sizeChain.ByteSize)
     return
    }
   }(fileName, expectedChecksum, i)
  }
 }

 // Wait for all goroutines to complete
 wg.Wait()
 close(errors)

 // Check for any errors
 var errStrings []string
 for err := range errors {
  if err != nil {
   errStrings = append(errStrings, err.Error())
  }
 }

 if len(errStrings) > 0 {
  t.Errorf("Found %d errors in concurrent execution:\n%s", 
   len(errStrings), strings.Join(errStrings, "\n"))
 }
}
    // Valid context with composer activity and package details processes successfully
func TestPHPCheckHandleProcessesComposerActivitySuccessfully(t *testing.T) {
    ctx := context.Background()

    activity := &model.Activity{
        ActivityHdr: model.ActivityHdr{
            Name: model.Composer,
        },
        Activity: model.PackageActivity{
            Package: "vendor/pkg",
        },
    }

    ctx = context.WithValue(ctx, ActCtxKey, activity)

    mockResp := &http.Response{
        Header: http.Header{
            "Content-Disposition": []string{"attachment; filename=PHPMailer-PHPMailer-v6.9.2-0-ga7b17b4.zip"},
        },
        Request: &http.Request{
            URL: &url.URL{
                Scheme: "https",
                Host:   "codeload.github.com",
                Path:   "/PHPMailer/PHPMailer/legacy.zip/a7b17b42fa4887c92146243f3d2f4ccb962af17c",
            },
            Host: "codeload.github.com",
        },
    }

    phpCheck := &PHPCheck{
        Response: mockResp,
    }

    err := phpCheck.Handle(ctx, bytes.NewReader([]byte{}))

    assert.NoError(t, err)

    pkgActivity, ok := activity.Activity.(model.PackageActivity)
    assert.True(t, ok)
    assert.Equal(t, "vendor/pkg", pkgActivity.Package)
    assert.Equal(t, "v6.9.2", pkgActivity.Version)
    assert.Equal(t, "codeload.github.com", pkgActivity.Repo)
}

    // Nil response returns early without error
func TestPHPCheckHandleNilResponseReturnsEarly(t *testing.T) {
    ctx := context.Background()

    activity := &model.Activity{
        ActivityHdr: model.ActivityHdr{
            Name: model.Composer,
        },
    }

    ctx = context.WithValue(ctx, ActCtxKey, activity)

    phpCheck := &PHPCheck{
        Response: nil,
    }

    err := phpCheck.Handle(ctx, bytes.NewReader([]byte{}))

    assert.NoError(t, err)
}
