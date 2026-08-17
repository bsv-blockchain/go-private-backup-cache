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

// DefaultMaxBlobBytes caps a single stored blob at 100 MiB, matching the network's maximum
// transaction size policy.
//
// It was 1 MiB, which made backup impossible for any wallet holding a large transaction.
// The R1-K1 YubiKey vault locking script is ~960 KB by design, so a single vault deposit is
// ~960 KB of rawTx and ~1.28 MB once the client base64-encodes it — over the old cap in one
// indivisible record. No client-side chunking can split a single record, so such a wallet
// could never push a backup again.
//
// SIZING THIS IS NOT FREE. The BRC-103/104 auth middleware wraps every handler in a
// ResponseWriterWrapper that buffers the whole request and response in order to sign them,
// and it implements neither http.Flusher nor http.Hijacker — so streaming is impossible
// behind auth and every byte is held in memory, several times over between the read
// buffer, the signature payload and the store write. Budget on the order of 3x this value
// per concurrent upload when setting a container memory limit, and lower MAX_BLOB_BYTES
// rather than hoping, if the deployment cannot afford it.
const DefaultMaxBlobBytes int64 = 100 << 20

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
