package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AnshRaj112/serenify-backend/internal/database"
)

func TestUploadQuotaKey(t *testing.T) {
	day := time.Date(2026, 8, 10, 15, 30, 0, 0, time.UTC)
	got := UploadQuotaKey("user-abc", day)
	want := "upload_quota:user-abc:2026-08-10"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSecondsUntilUTCMidnight(t *testing.T) {
	now := time.Date(2026, 8, 10, 23, 59, 0, 0, time.UTC)
	d := secondsUntilUTCMidnight(now)
	if d < 59*time.Second || d > 61*time.Second {
		t.Fatalf("expected ~60s until midnight, got %v", d)
	}

	near := time.Date(2026, 8, 10, 23, 59, 59, 500e6, time.UTC)
	d2 := secondsUntilUTCMidnight(near)
	if d2 < time.Second {
		t.Fatalf("TTL must be at least 1s, got %v", d2)
	}
}

func TestCheckAndConsumeUploadQuota_NilRedisFailsClosed(t *testing.T) {
	prev := database.RedisClient
	database.RedisClient = nil
	t.Cleanup(func() { database.RedisClient = prev })

	_, err := CheckAndConsumeUploadQuota(context.Background(), "user-1")
	if !errors.Is(err, ErrUploadQuotaUnavailable) {
		t.Fatalf("got %v want ErrUploadQuotaUnavailable", err)
	}
}
