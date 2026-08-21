// Package client is the Go consumer of the private backup cache service.
//
// It speaks the auth-proof protocol (docs/authproof-protocol.md): every request carries one
// signed header built against the server's identity key, which the client learns from the
// unauthenticated /v1/limits endpoint on first use. Bodies stream in both directions —
// nothing here buffers a blob, because blobs run to hundreds of megabytes.
//
// Entry, DeviceSummary and Limits mirror the server's wire shapes instead of importing
// them: the server's own types live under internal/, which a consumer of this package
// could never name in its code. The authproof import is different — it never appears in
// this package's API, so consumers compile against it without being able to see it.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/authproof"
)

// contentTypeOctetStream is the only upload encoding the service accepts.
const contentTypeOctetStream = "application/octet-stream"

// Limits is the service's published operating envelope, from GET /v1/limits.
type Limits struct {
	MaxBlobBytes      int64  `json:"maxBlobBytes"`
	MaxBodyBytes      int64  `json:"maxBodyBytes"`
	ServerIdentityKey string `json:"serverIdentityKey"`
}

// Entry is one log entry's metadata, as reported by Index.
type Entry struct {
	Seq        int       `json:"seq"`
	Sha256     string    `json:"sha256"`
	PrevSha256 string    `json:"prevSha256,omitempty"`
	Size       int       `json:"size"`
	CreatedAt  time.Time `json:"createdAt"`
}

// DeviceSummary describes one device's log head, as reported by Manifest.
type DeviceSummary struct {
	DeviceID   string    `json:"deviceId"`
	Generation int       `json:"generation"`
	HeadSeq    int       `json:"headSeq"`
	HeadSha256 string    `json:"headSha256"`
	TotalBytes int64     `json:"totalBytes"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// AppendResult is the server's confirmation of a stored blob. Sha256 is computed
// server-side from the streamed bytes — comparing it against the digest you uploaded under
// is the end-to-end integrity check.
type AppendResult struct {
	Seq    int
	Sha256 string
	Size   int64
}

// APIError is any non-2xx answer, decoded from the service's error envelope. Code is the
// stable machine-readable field ("ERR_SEQ_CONFLICT", "ERR_BLOB_NOT_FOUND", ...); match on
// it, not on Message.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("backup cache: %d %s: %s", e.Status, e.Code, e.Message)
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient substitutes the transport, e.g. to set timeouts or a proxy. Uploads and
// downloads stream, so a whole-request timeout on the http.Client bounds blob size in
// practice — prefer transport-level timeouts for large blobs.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// Client talks to one backup cache service as one identity. Safe for concurrent use.
type Client struct {
	baseURL   string
	http      *http.Client
	wallet    sdkwallet.Interface
	walletErr error

	// limits is fetched at most once per client, lazily: the server's identity key is
	// needed before the first proof can be signed. The mutex rather than sync.Once is
	// deliberate — a failed fetch must stay retryable on the next call.
	mu     sync.Mutex
	limits *Limits
}

// New builds a client for the service at baseURL, authenticating as priv. The account is
// the public key of priv: every blob written through this client is readable only by a
// client holding the same key.
//
// A wallet that cannot be built (nil or invalid key) is reported by the first call rather
// than here, so construction stays infallible and composable.
func New(baseURL string, priv *ec.PrivateKey, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    http.DefaultClient,
	}
	c.wallet, c.walletErr = sdkwallet.NewCompletedProtoWallet(priv)
	for _, o := range opts {
		o(c)
	}
	return c
}

// Limits reports the service's blob cap and identity key, fetching them on first call and
// caching thereafter. Unauthenticated by design — a client needs the server's identity key
// BEFORE it can sign anything.
func (c *Client) Limits(ctx context.Context) (Limits, error) {
	// The lock is held across the fetch so concurrent first calls collapse into one
	// request; on failure limits stays nil and the next caller retries.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limits != nil {
		return *c.limits, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/limits", nil)
	if err != nil {
		return Limits{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Limits{}, fmt.Errorf("fetch limits: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Limits{}, decodeAPIError(resp)
	}
	defer closeQuietly(resp.Body)

	var lim Limits
	if err := json.NewDecoder(resp.Body).Decode(&lim); err != nil {
		return Limits{}, fmt.Errorf("decode limits: %w", err)
	}
	if lim.ServerIdentityKey == "" {
		return Limits{}, errors.New("limits response carries no serverIdentityKey")
	}
	c.limits = &lim
	return lim, nil
}

// Append streams body to the log as (deviceID, generation, seq). bodySha256 is the
// lowercase hex sha256 of the body, precomputed by the caller — it is signed into the auth
// proof, which is what lets the body itself stream unbuffered on both ends. size sets
// Content-Length when known (> 0); pass 0 to send chunked. prevSha256 chains the entry to
// its predecessor and is empty for the first entry of a generation.
//
// The returned Sha256 is the server's own hash of what it stored; a caller that compares
// it with bodySha256 has verified the upload end to end.
func (c *Client) Append(ctx context.Context, deviceID string, generation, seq int, prevSha256 string, body io.Reader, bodySha256 string, size int64) (AppendResult, error) {
	requestURI := fmt.Sprintf("/v1/log/%s?seq=%d&generation=%d", url.PathEscape(deviceID), seq, generation)
	if prevSha256 != "" {
		requestURI += "&prevSha256=" + url.QueryEscape(prevSha256)
	}

	resp, err := c.do(ctx, http.MethodPost, requestURI, bodySha256, body, size)
	if err != nil {
		return AppendResult{}, err
	}
	defer closeQuietly(resp.Body)

	var out struct {
		Seq    int    `json:"seq"`
		Sha256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return AppendResult{}, fmt.Errorf("decode append response: %w", err)
	}
	return AppendResult{Seq: out.Seq, Sha256: out.Sha256, Size: out.Size}, nil
}

// AppendBytes appends an in-memory blob, computing its digest itself. For blobs too large
// to hold in memory, hash while producing them and use Append directly.
func (c *Client) AppendBytes(ctx context.Context, deviceID string, generation, seq int, prevSha256 string, data []byte) (AppendResult, error) {
	sum := sha256.Sum256(data)
	return c.Append(ctx, deviceID, generation, seq, prevSha256,
		bytes.NewReader(data), hex.EncodeToString(sum[:]), int64(len(data)))
}

// Blob streams one stored blob back. The caller owns the reader and must close it; size is
// the blob's full length, known up front so restores can report progress.
func (c *Client) Blob(ctx context.Context, deviceID string, generation, seq int) (io.ReadCloser, int64, error) {
	requestURI := fmt.Sprintf("/v1/log/%s/%d?generation=%d", url.PathEscape(deviceID), seq, generation)
	resp, err := c.do(ctx, http.MethodGet, requestURI, "", nil, 0)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// Index lists entry metadata for one generation, starting at sequence from. Pass 0 for
// from and limit to take the server's defaults; the server caps limit regardless.
func (c *Client) Index(ctx context.Context, deviceID string, generation, from, limit int) ([]Entry, error) {
	requestURI := fmt.Sprintf("/v1/log/%s?generation=%d", url.PathEscape(deviceID), generation)
	if from > 0 {
		requestURI += fmt.Sprintf("&from=%d", from)
	}
	if limit > 0 {
		requestURI += fmt.Sprintf("&limit=%d", limit)
	}

	resp, err := c.do(ctx, http.MethodGet, requestURI, "", nil, 0)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(resp.Body)

	var out struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode index response: %w", err)
	}
	return out.Entries, nil
}

// Manifest summarises every device and generation this identity has stored. This is the
// restore entry point: a fresh install derives its key from the recovered seed, calls
// this, and picks a device and generation to replay.
func (c *Client) Manifest(ctx context.Context) ([]DeviceSummary, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/manifest", "", nil, 0)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(resp.Body)

	var out struct {
		Devices []DeviceSummary `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode manifest response: %w", err)
	}
	return out.Devices, nil
}

// PruneGeneration deletes a whole superseded generation after a compaction. The server
// refuses the newest two (ERR_RETENTION_GUARD), so a bug here cannot destroy the only
// recoverable backup.
func (c *Client) PruneGeneration(ctx context.Context, deviceID string, generation int) error {
	requestURI := fmt.Sprintf("/v1/generation/%s/%d", url.PathEscape(deviceID), generation)
	resp, err := c.do(ctx, http.MethodDelete, requestURI, "", nil, 0)
	if err != nil {
		return err
	}
	closeQuietly(resp.Body)
	return nil
}

// DeleteAccount erases every blob this identity has stored, across all devices and
// generations, ignoring the retention guard. Idempotent: erasing an empty account returns
// deleted == 0, not an error, so a client that lost the first response can safely retry.
func (c *Client) DeleteAccount(ctx context.Context) (int64, error) {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/account", "", nil, 0)
	if err != nil {
		return 0, err
	}
	defer closeQuietly(resp.Body)

	var out struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode delete response: %w", err)
	}
	return out.Deleted, nil
}

// do signs and executes one request, converting any non-2xx answer into *APIError. On
// success the caller owns resp.Body.
//
// requestURI must be the exact path-plus-query that goes on the wire: the proof signs
// "METHOD requestURI", and the server rebuilds that string from the request line verbatim.
// Every requestURI this package emits uses only unreserved characters or percent-escapes,
// so url.Parse inside http.NewRequest round-trips it byte for byte.
func (c *Client) do(ctx context.Context, method, requestURI, bodySha256 string, body io.Reader, size int64) (*http.Response, error) {
	if c.walletErr != nil {
		return nil, fmt.Errorf("client has no usable key: %w", c.walletErr)
	}
	lim, err := c.Limits(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.roundTrip(ctx, lim.ServerIdentityKey, method, requestURI, bodySha256, body, size)

	// net/http transparently re-sends a bodyless request whose reused keep-alive connection
	// died — byte-identical, same proof header — so when the server had in fact processed
	// the first copy, the invisible second copy hits the replay guard and the caller sees
	// "proof already used" for a request it only ever issued once. Signing a fresh proof and
	// retrying exactly once recovers that case. Only bodyless requests qualify: a replayed
	// Append proof means the first copy may already have stored the entry, so re-signing
	// would double-append rather than recover, and its body reader is consumed anyway.
	if body == nil && isSpentProofRefusal(err) {
		return c.roundTrip(ctx, lim.ServerIdentityKey, method, requestURI, bodySha256, nil, 0)
	}
	return resp, err
}

// isSpentProofRefusal reports whether err is the server's replay guard refusing a proof it
// has already accepted once — the signature a transparent keep-alive re-send leaves behind.
func isSpentProofRefusal(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.Status == http.StatusUnauthorized &&
		apiErr.Code == "ERR_AUTH_REQUIRED" &&
		strings.Contains(apiErr.Message, "proof already used")
}

// roundTrip signs one proof and executes one request attempt. Split from do so a retry
// gets a genuinely fresh proof — new nonce, new timestamp — rather than a re-send.
func (c *Client) roundTrip(ctx context.Context, serverIdentityKey, method, requestURI, bodySha256 string, body io.Reader, size int64) (*http.Response, error) {
	proof, err := authproof.Sign(ctx, c.wallet, serverIdentityKey,
		authproof.Action(method, requestURI, bodySha256), time.Now())
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	header, err := authproof.Encode(proof)
	if err != nil {
		return nil, fmt.Errorf("encode proof: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+requestURI, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authproof.Header, header)
	if body != nil {
		req.Header.Set("Content-Type", contentTypeOctetStream)
		// Content-Length lets the server refuse an oversize upload before reading it;
		// without a size the body goes chunked and the server counts as it streams.
		if size > 0 {
			req.ContentLength = size
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeAPIError(resp)
	}
	return resp, nil
}

// decodeAPIError drains and closes an error response. An unparseable body still yields a
// usable *APIError — the HTTP status alone identifies most failures.
func decodeAPIError(resp *http.Response) error {
	defer closeQuietly(resp.Body)
	var envelope struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = json.Unmarshal(raw, &envelope)
	return &APIError{Status: resp.StatusCode, Code: envelope.Code, Message: envelope.Description}
}

// closeQuietly discards a close error: by the time it fires the response has already been
// decoded or abandoned, so there is nothing actionable in it.
func closeQuietly(c io.Closer) { _ = c.Close() }
