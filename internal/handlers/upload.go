package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"

	"github.com/AnshRaj112/serenify-backend/internal/config"
	"github.com/AnshRaj112/serenify-backend/internal/services"
)

const maxUploadParseBytes = 10 << 20 // 10MB

// cloudinaryUploader is the subset of CloudinaryService used by handlers.
type cloudinaryUploader interface {
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (string, error)
	UploadString(ctx context.Context, content, folder, filename string) (string, error)
}

var cloudinaryService cloudinaryUploader

// resolveUploadPrincipalFn is overridable in tests.
var resolveUploadPrincipalFn = resolveUploadPrincipal

// checkUploadQuotaFn is overridable in tests.
var checkUploadQuotaFn = services.CheckAndConsumeUploadQuota

func InitCloudinaryService(cfg *config.Config) error {
	service, err := services.NewCloudinaryService(
		cfg.CloudinaryName,
		cfg.CloudinaryAPIKey,
		cfg.CloudinaryAPISecret,
	)
	if err != nil {
		return err
	}
	cloudinaryService = service
	return nil
}

type UploadResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
}

// resolveUploadPrincipal accepts any authenticated principal (user/therapist session,
// admin session, therapist JWT, or receptionist JWT). Returns a stable quota key ID.
func resolveUploadPrincipal(r *http.Request) (principalID string, ok bool) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return "", false
	}

	if userID, valid, err := services.ValidateSession(token); err == nil && valid {
		return userID.String(), true
	}
	if adminID, valid, err := services.ValidateAdminSession(token); err == nil && valid {
		return "admin:" + adminID.String(), true
	}
	if claims, valid := services.ValidateAccessToken(token); valid && claims != nil && claims.UserID != "" {
		return claims.UserID, true
	}
	if claims, valid := services.ValidateReceptionistAccessToken(token); valid && claims != nil && claims.UserID != "" {
		return "receptionist:" + claims.UserID, true
	}
	return "", false
}

func writeUploadJSON(w http.ResponseWriter, status int, resp UploadResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// UploadFile handles authenticated file uploads to Cloudinary.
// Auth is required. CORS is handled exclusively by the global allowlist middleware —
// this handler must never set Access-Control-Allow-Origin.
func UploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeUploadJSON(w, http.StatusMethodNotAllowed, UploadResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	principalID, ok := resolveUploadPrincipalFn(r)
	if !ok {
		writeUploadJSON(w, http.StatusUnauthorized, UploadResponse{
			Success: false,
			Message: "Authentication required",
		})
		return
	}

	remaining, err := checkUploadQuotaFn(r.Context(), principalID)
	if err != nil {
		if errors.Is(err, services.ErrUploadQuotaExceeded) {
			w.Header().Set("X-Upload-Quota-Limit", strconv.Itoa(services.UploadQuotaPerDay))
			w.Header().Set("X-Upload-Quota-Remaining", "0")
			writeUploadJSON(w, http.StatusTooManyRequests, UploadResponse{
				Success: false,
				Message: "Daily upload quota exceeded. Try again tomorrow.",
			})
			return
		}
		log.Printf("ERROR: upload quota check failed for %s: %v", principalID, err)
		writeUploadJSON(w, http.StatusServiceUnavailable, UploadResponse{
			Success: false,
			Message: "Upload temporarily unavailable",
		})
		return
	}
	w.Header().Set("X-Upload-Quota-Limit", strconv.Itoa(services.UploadQuotaPerDay))
	w.Header().Set("X-Upload-Quota-Remaining", strconv.Itoa(remaining))

	if cloudinaryService == nil {
		log.Printf("ERROR: Cloudinary service is nil")
		writeUploadJSON(w, http.StatusInternalServerError, UploadResponse{
			Success: false,
			Message: "Upload service not configured",
		})
		return
	}

	if err := r.ParseMultipartForm(maxUploadParseBytes); err != nil {
		log.Printf("ERROR: Failed to parse multipart form: %v", err)
		writeUploadJSON(w, http.StatusBadRequest, UploadResponse{
			Success: false,
			Message: "Invalid or oversized upload (max 10MB)",
		})
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		log.Printf("ERROR: Failed to get file from form: %v", err)
		writeUploadJSON(w, http.StatusBadRequest, UploadResponse{
			Success: false,
			Message: "No file provided",
		})
		return
	}
	defer file.Close()

	folder := r.URL.Query().Get("folder")
	log.Printf("Uploading file for %s: %s, size: %d bytes, type: %s, folder: %s",
		principalID, fileHeader.Filename, fileHeader.Size, fileHeader.Header.Get("Content-Type"), folder)

	url, err := cloudinaryService.UploadFile(r.Context(), file, fileHeader, folder)
	if err != nil {
		log.Printf("ERROR: Cloudinary upload failed: %v", err)
		writeUploadJSON(w, http.StatusInternalServerError, UploadResponse{
			Success: false,
			Message: "Failed to upload file",
		})
		return
	}

	if url == "" {
		log.Printf("ERROR: Cloudinary returned empty URL")
		writeUploadJSON(w, http.StatusInternalServerError, UploadResponse{
			Success: false,
			Message: "Upload succeeded but no URL returned",
		})
		return
	}

	log.Printf("File uploaded successfully to Cloudinary for %s: %s", principalID, url)
	writeUploadJSON(w, http.StatusOK, UploadResponse{
		Success: true,
		Message: "File uploaded successfully",
		URL:     url,
	})
}
