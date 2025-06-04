package utils

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/invisirisk/clog"
	"github.com/invisirisk/svcs/model"
)

type activityCtxKey struct{}
type secretCtxKey struct{}

var (
	ActCtxKey       = activityCtxKey{}
	SecretPolicyCtx = secretCtxKey{}

	alertLevel = map[model.AlertLevel]int{
		model.AlertNone:     0,
		model.AlertWarning:  1,
		model.AlertError:    2,
		model.AlertCritical: 3,
	}
)

type Chain interface {
	Handle(ctx context.Context, r io.Reader) error
}
func AlertLt(left, right model.AlertLevel) bool {
	return alertLevel[left] < alertLevel[right]
}
func appendCheck(ctx context.Context, check ...model.TechCheck) {
	cl := clog.FromCtx(ctx)
	v := ctx.Value(ActCtxKey)

	if act, ok := v.(*model.Activity); ok {
		for _, ch := range check {
			if act.AlertLevel != model.AlertNone && act.Decision != model.Deny {
				act.Decision = model.Alert
			}

			if AlertLt(act.AlertLevel, ch.AlertLevel) {
				act.AlertLevel = ch.AlertLevel
			}
		}
		act.Checks = append(act.Checks, check...)
	} else {
		cl.Errorf("invalid activity type %T", v)
	}
}
type ResponseData struct{
	Response *http.Response
	Mime string
	Checksum string // md5 checksum
	FileSizeByte int64
}
func ReaderChain(ctx context.Context, bottom io.ReadCloser, chains ...Chain) io.ReadCloser {
    // Read initial content
    content, err := io.ReadAll(bottom)
    if err != nil {
        log.Printf("Error reading initial content: %v", err)
        return bottom
    }

    cl := clog.FromCtx(ctx)
    cl.Infof("content size %v", len(content))

    // Process through each chain sequentially
    for _, chain := range chains {
        // Create a new reader for each chain to ensure data is not consumed
        chainReader := bytes.NewReader(content)

        if err := chain.Handle(ctx, chainReader); err != nil {
            log.Printf("Error in chain.Handle: %v", err)
            return io.NopCloser(bytes.NewReader(content)) // Return original content on error
        }
    }

    // Return the final processed content
    return io.NopCloser(bytes.NewReader(content))
}

type MimeChain struct {
	Direction string
	Mime      string
}

func (mc *MimeChain) Handle(ctx context.Context, r io.Reader) error {
	_, cl := clog.WithCtx(ctx, "mime")
	m, err := mimetype.DetectReader(r)
	if err != nil {
		cl.Errorf("error calculating mime type %v", err)
		return nil
	}
	mc.Mime = m.String()
	cl.Infof("mime type %v", m)


	return nil
}

type Checksum struct {
	Direction string
	Checksum  string
}

func (sc *Checksum) Handle(ctx context.Context, r io.Reader) error {
	// Calculate the MD5 checksum of the content and adds it to the activity log
	_, cl := clog.WithCtx(ctx, "md5")
	h := md5.New()
	if _, err := io.Copy(h, r); err != nil {
		cl.Errorf("error %v calculating checksum")
	}
	sc.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	log.Print("Checksum: ", sc.Checksum)

	return nil
}

type PHPCheck struct {
	Response *http.Response
}

// Handle inspects the response and extracts the package name and version.
//
// It only extracts info if the activity is a Composer activity.
//
// It uses the Content-Disposition header to determine the package name and version.
//
// If the content disposition header is not present, it does not extract the package info.
func (sc *PHPCheck) Handle(ctx context.Context, r io.Reader) error {
	_, cl := clog.WithCtx(ctx, "php")

	if sc.Response == nil {
		cl.Errorf("no response")
		return nil
	}

	// Log the context
	v := ctx.Value(ActCtxKey)
	if act, ok := v.(*model.Activity); ok {
		cl.Infof("activity %v", act)
		if act.ActivityHdr.Name != model.Composer {
			cl.Infof("not composer")
			return nil
		}

		var packageName string

		if activityDetail, ok := act.Activity.(model.PackageActivity); ok {
			cl.Infof("package name from activity: %v", activityDetail.Package)
			packageName = activityDetail.Package
		} else {
			packageName = ""
		}

		contentDisposition := sc.Response.Header.Get("Content-Disposition")
		if contentDisposition != "" {
			cl.Infof("DEBUG: content disposition %v", contentDisposition)
		}

		// Get the URL
		url := sc.Response.Request.URL
		cl.Infof("url %v", url)

		vendor, name, version, err := ExtractPackageInfo(url.String(), contentDisposition)
		if err != nil {
			cl.Errorf("error %v extracting package info", err)
			return nil
		}
		if packageName == "" {
			packageName = vendor + "/" + name
		}
		act.Activity = model.PackageActivity{
			Package: packageName,
			Version: version,
			Repo:    sc.Response.Request.Host,
		}
	}

	return nil
}

// ExtractPackageInfo extracts the vendor, package name and version from a URL and Content-Disposition HTTP header.
//
// The URL is expected to be in the format:
// https://codeload.github.com/PHPMailer/PHPMailer/legacy.zip/a7b17b42fa4887c92146243f3d2f4ccb962af17c
//
// The Content-Disposition header is expected to be in the format:
// attachment; filename=PHPMailer-PHPMailer-v6.9.2-0-ga7b17b4.zip
//
// The function returns an error if the URL or Content-Disposition header is not in the expected format.
func ExtractPackageInfo(url, disposition string) (vendor, packageName, version string, err error) {
	// Extract vendor and package name from URL
	urlParts := strings.Split(url, "/")
	fmt.Printf("Urlparts: %d", len(urlParts))
	fmt.Printf("Part 4: %s", urlParts[5])
	if len(urlParts) < 6 || urlParts[5] != "legacy.zip" {
		return "", "", "", fmt.Errorf("invalid URL format: %s", url)
	}
	vendor = urlParts[3]
	packageName = urlParts[4]

	index := strings.Index(disposition, "filename=")
	if index == -1 {
		fmt.Println("filename not found")
		return
	}

	filename := disposition[index+9:]

	filename_parts := strings.Split(filename, "-")
	if len(filename_parts) < 3 {
		fmt.Println("Not enough hyphens found")
		return
	}

	filename_version := strings.Join(filename_parts[:len(filename_parts)-2], "-")

	filename_version_url := strings.ToLower(vendor) + "-" + strings.ToLower(packageName)

	version_index := strings.Index(strings.ToLower(filename_version), filename_version_url+"-")
	if version_index == -1 {
		fmt.Println("Version not found")
		return
	}

	version = filename_version[len(filename_version_url)+1:]

	return vendor, packageName, version, nil
}
type FileSize struct {
	Direction string
	ByteSize int64
}

func (sc *FileSize) Handle(ctx context.Context, r io.Reader) error {
	// Calculate the byte size of the content and adds it to the activity log
	_, cl := clog.WithCtx(ctx, "file_size")
	size, err := io.Copy(io.Discard, r)
	if err != nil {
		cl.Errorf("failed to calculate size: %v", err)
		return nil
	}
	sc.ByteSize = size
	cl.Infof("size %v bytes", sc.ByteSize)

	return nil
}