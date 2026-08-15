// Package config loads service configuration from the environment.
//
// Plain os.Getenv with a typed struct, matching the house style of the other small BSV
// services. There is deliberately no config file and no viper.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// DefaultMaxBlobBytes caps a single stored blob at 1 MiB.
//
// This is not a defensive nicety. The BRC-103/104 auth middleware wraps every handler in a
// ResponseWriterWrapper that buffers the whole request and response in order to sign them,
// and it implements neither http.Flusher nor http.Hijacker — so streaming is impossible
// behind auth and every byte is held in memory. The cap is what keeps that safe.
const DefaultMaxBlobBytes int64 = 1 << 20

// Config is the fully resolved service configuration.
type Config struct {
	Port             int
	ServerPrivateKey string
	DatabaseURL      string
	LogLevel         string
	LogFormat        string
	MaxBlobBytes     int64
}

// Load reads configuration from the environment.
//
// It fails fast when SERVER_PRIVATE_KEY is missing or malformed. Every route on this
// service is authenticated, so a server without an identity cannot do anything useful and
// should not start pretending otherwise.
func Load() (*Config, error) {
	key := os.Getenv("SERVER_PRIVATE_KEY")
	if key == "" {
		return nil, errors.New("SERVER_PRIVATE_KEY is not defined in environment variables")
	}
	if err := validateHexKey(key); err != nil {
		return nil, err
	}

	return &Config{
		Port:             getEnvInt("PORT", 8080),
		ServerPrivateKey: key,
		DatabaseURL:      getEnvDefault("DATABASE_URL", ""),
		LogLevel:         getEnvDefault("LOG_LEVEL", "info"),
		LogFormat:        getEnvDefault("LOG_FORMAT", "json"),
		MaxBlobBytes:     int64(getEnvInt("MAX_BLOB_BYTES", int(DefaultMaxBlobBytes))),
	}, nil
}

func validateHexKey(key string) error {
	if len(key) != 64 {
		return fmt.Errorf("SERVER_PRIVATE_KEY must be 64 hex characters, got %d", len(key))
	}
	for _, c := range key {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return errors.New("SERVER_PRIVATE_KEY must be hexadecimal")
		}
	}
	return nil
}

func getEnvDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getEnvInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}
