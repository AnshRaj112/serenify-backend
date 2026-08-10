package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AnshRaj112/serenify-backend/internal/database"
)

const (
	// UploadQuotaPerDay is the maximum number of successful Cloudinary uploads
	// allowed per authenticated principal per UTC calendar day.
	UploadQuotaPerDay = 20

	// UploadQuotaKeyPrefix is the Redis key prefix for daily upload counters.
	UploadQuotaKeyPrefix = "upload_quota:"
)

var (
	// ErrUploadQuotaExceeded is returned when the principal has used their daily upload allotment.
	ErrUploadQuotaExceeded = errors.New("upload quota exceeded")
	// ErrUploadQuotaUnavailable is returned when Redis is unavailable to enforce quotas.
	ErrUploadQuotaUnavailable = errors.New("upload quota service unavailable")
)

// UploadQuotaKey builds the Redis key for a principal's daily upload counter.
func UploadQuotaKey(principalID string, day time.Time) string {
	return fmt.Sprintf("%s%s:%s", UploadQuotaKeyPrefix, principalID, day.UTC().Format("2006-01-02"))
}

// secondsUntilUTCMidnight returns TTL seconds until the next UTC midnight (minimum 1).
func secondsUntilUTCMidnight(now time.Time) time.Duration {
	utc := now.UTC()
	next := time.Date(utc.Year(), utc.Month(), utc.Day()+1, 0, 0, 0, 0, time.UTC)
	d := next.Sub(utc)
	if d < time.Second {
		return time.Second
	}
	return d
}

// CheckAndConsumeUploadQuota atomically increments the daily upload counter.
// Returns ErrUploadQuotaExceeded when the limit would be surpassed.
// Fails closed if Redis is unavailable (cost-sensitive control).
func CheckAndConsumeUploadQuota(ctx context.Context, principalID string) (remaining int, err error) {
	if principalID == "" {
		return 0, errors.New("principal ID required")
	}
	if database.RedisClient == nil {
		return 0, ErrUploadQuotaUnavailable
	}

	now := time.Now().UTC()
	key := UploadQuotaKey(principalID, now)
	ttlSeconds := int(secondsUntilUTCMidnight(now).Seconds())

	// Atomic: INCR then set TTL on first write; reject if over limit (and roll back).
	lua := `
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local ttl = tonumber(ARGV[2])
		local count = redis.call("INCR", key)
		if count == 1 then
			redis.call("EXPIRE", key, ttl)
		end
		if count > limit then
			redis.call("DECR", key)
			return -1
		end
		return limit - count
	`

	res, err := database.RedisClient.Eval(ctx, lua, []string{key}, UploadQuotaPerDay, ttlSeconds).Int()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUploadQuotaUnavailable, err)
	}
	if res < 0 {
		return 0, ErrUploadQuotaExceeded
	}
	return res, nil
}
