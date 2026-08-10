package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AnshRaj112/serenify-backend/internal/middleware"
	"github.com/AnshRaj112/serenify-backend/internal/services"
)

type stubUploader struct {
	url string
	err error
}

func (s *stubUploader) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (string, error) {
	return s.url, s.err
}

func (s *stubUploader) UploadString(ctx context.Context, content, folder, filename string) (string, error) {
	return s.url, s.err
}

func withUploadTestHooks(t *testing.T, principal string, remaining int, quotaErr error, uploader cloudinaryUploader) {
	t.Helper()
	prevResolve := resolveUploadPrincipalFn
	prevQuota := checkUploadQuotaFn
	prevCloud := cloudinaryService

	resolveUploadPrincipalFn = func(r *http.Request) (string, bool) {
		if principal == "" {
			return "", false
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return "", false
		}
		return principal, true
	}
	checkUploadQuotaFn = func(ctx context.Context, principalID string) (int, error) {
		if quotaErr != nil {
			return 0, quotaErr
		}
		return remaining, nil
	}
	cloudinaryService = uploader

	t.Cleanup(func() {
		resolveUploadPrincipalFn = prevResolve
		checkUploadQuotaFn = prevQuota
		cloudinaryService = prevCloud
	})
}

func multipartUploadRequest(t *testing.T, fieldName, filename, content, authHeader string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return req
}

func decodeUploadResponse(t *testing.T, rec *httptest.ResponseRecorder) UploadResponse {
	t.Helper()
	var resp UploadResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	return resp
}

// Security: unauthenticated POST must 401 (ISSUE-SAL-001).
func TestUploadFile_UnauthenticatedReturns401(t *testing.T) {
	withUploadTestHooks(t, "", 0, nil, &stubUploader{url: "https://example.com/x"})

	req := multipartUploadRequest(t, "file", "a.png", "pngdata", "")
	rec := httptest.NewRecorder()
	UploadFile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec)
	if resp.Success || resp.Message != "Authentication required" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if ao := rec.Header().Get("Access-Control-Allow-Origin"); ao == "*" {
		t.Fatal("handler must not set Access-Control-Allow-Origin: *")
	}
}

// Security: invalid/missing Bearer still 401.
func TestUploadFile_InvalidBearerReturns401(t *testing.T) {
	withUploadTestHooks(t, "", 0, nil, &stubUploader{url: "https://example.com/x"})

	req := multipartUploadRequest(t, "file", "a.png", "pngdata", "Bearer not-a-real-session")
	rec := httptest.NewRecorder()
	UploadFile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
}

// Regression: authenticated upload still succeeds for legitimate roles.
func TestUploadFile_AuthenticatedSucceeds(t *testing.T) {
	withUploadTestHooks(t, "user-123", 19, nil, &stubUploader{url: "https://res.cloudinary.com/demo/image.png"})

	req := multipartUploadRequest(t, "file", "a.png", "pngdata", "Bearer valid-token")
	rec := httptest.NewRecorder()
	UploadFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec)
	if !resp.Success || resp.URL == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if rec.Header().Get("X-Upload-Quota-Limit") != "20" {
		t.Fatalf("missing quota limit header: %v", rec.Header())
	}
	if ao := rec.Header().Get("Access-Control-Allow-Origin"); ao == "*" {
		t.Fatal("handler must not set Access-Control-Allow-Origin: *")
	}
}

// Unit: daily quota enforcement returns 429.
func TestUploadFile_QuotaExceededReturns429(t *testing.T) {
	withUploadTestHooks(t, "user-123", 0, services.ErrUploadQuotaExceeded, &stubUploader{url: "https://example.com/x"})

	req := multipartUploadRequest(t, "file", "a.png", "pngdata", "Bearer valid-token")
	rec := httptest.NewRecorder()
	UploadFile(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}
}

// Security / CORS: handler never emits *; global allowlist middleware still works.
func TestUploadFile_CORSUsesGlobalAllowlistNotStar(t *testing.T) {
	allowed := []string{"https://www.salvioris.com", "http://localhost:3000"}
	handler := middleware.CORS(allowed)(http.HandlerFunc(UploadFile))

	t.Run("allowed origin echoes allowlist value", func(t *testing.T) {
		withUploadTestHooks(t, "user-123", 19, nil, &stubUploader{url: "https://res.cloudinary.com/demo/image.png"})
		req := multipartUploadRequest(t, "file", "a.png", "pngdata", "Bearer valid-token")
		req.Header.Set("Origin", "https://www.salvioris.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
		}
		got := rec.Header().Get("Access-Control-Allow-Origin")
		if got != "https://www.salvioris.com" {
			t.Fatalf("Allow-Origin=%q want allowlisted origin", got)
		}
		if got == "*" {
			t.Fatal("must not be *")
		}
	})

	t.Run("disallowed origin gets no Allow-Origin", func(t *testing.T) {
		withUploadTestHooks(t, "", 0, nil, &stubUploader{url: "https://example.com/x"})
		req := multipartUploadRequest(t, "file", "a.png", "pngdata", "")
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if ao := rec.Header().Get("Access-Control-Allow-Origin"); ao != "" {
			t.Fatalf("disallowed origin should not get Allow-Origin, got %q", ao)
		}
		if ao := rec.Header().Get("Access-Control-Allow-Origin"); ao == "*" {
			t.Fatal("must not be *")
		}
	})
}

// Integration-style: missing file field after auth still fails cleanly (no raw error leak).
func TestUploadFile_MissingFileReturns400(t *testing.T) {
	withUploadTestHooks(t, "user-123", 19, nil, &stubUploader{url: "https://example.com/x"})

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("notfile", "x")
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer valid-token")

	rec := httptest.NewRecorder()
	UploadFile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	resp := decodeUploadResponse(t, rec)
	if strings.Contains(resp.Message, "multipart:") || strings.Contains(resp.Message, "http:") {
		t.Fatalf("must not leak raw error: %q", resp.Message)
	}
}
