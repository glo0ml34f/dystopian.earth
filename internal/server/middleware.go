package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
)

const (
	bruteForceWindow    = 60 * time.Second
	bruteForceThreshold = 10
	bruteForceBaseLock  = 30 * time.Second
	bruteForceMaxLock   = 2 * time.Hour
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (s *Server) postShield(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || s.redisPool == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r)
		if ip == "" {
			next.ServeHTTP(w, r)
			return
		}

		conn := s.redisPool.Get()
		defer conn.Close()

		lockKey := "lockout:" + ip
		if ttl, err := redis.Int(conn.Do("TTL", lockKey)); err == nil && ttl > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(ttl))
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		} else if exists, err := redis.Bool(conn.Do("EXISTS", lockKey)); err == nil && exists {
			w.Header().Set("Retry-After", strconv.Itoa(int(bruteForceBaseLock/time.Second)))
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}

		attemptKey := "post:attempts:" + ip
		attempts, err := redis.Int(conn.Do("INCR", attemptKey))
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		_, _ = conn.Do("EXPIRE", attemptKey, int(bruteForceWindow/time.Second))

		if attempts > bruteForceThreshold {
			exponent := attempts - bruteForceThreshold
			lockDuration := bruteForceBaseLock << (exponent - 1)
			if lockDuration > bruteForceMaxLock {
				lockDuration = bruteForceMaxLock
			}
			seconds := int(lockDuration / time.Second)
			_, _ = conn.Do("SETEX", lockKey, seconds, "1")
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		if recorder.status < http.StatusBadRequest {
			_, _ = conn.Do("DEL", attemptKey)
		}
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		candidate := strings.TrimSpace(parts[0])
		if candidate != "" {
			return candidate
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
