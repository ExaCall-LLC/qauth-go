package qauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Error is the SDK's one error type. Every refusal is an *Error: an answer
// from qAuth, a token this backend refused, or qAuth out of reach.
//
// Match a kind of refusal with errors.Is against the Err* values (it
// compares Code), or read the fields with errors.As.
type Error struct {
	// Status is the HTTP status to answer with (0 when qAuth could not be
	// reached).
	Status int
	// Code is stable, e.g. FORBIDDEN, RATE_LIMITED, TOKEN_EXPIRED.
	Code string
	// Message is in plain words; you can show it.
	Message string
	// RequestID is qAuth's request id, for support (when qAuth answered).
	RequestID string
	// Fields holds field-level messages of a 422 answer.
	Fields map[string][]string
	// RetryAfter is how long to wait before trying again (from Retry-After,
	// on 429 and some 503 answers); 0 when qAuth did not say.
	RetryAfter time.Duration
	// Data is what came with the refusal, when qAuth sent something (the
	// envelope's data, as JSON), e.g. the ways to confirm with a 403
	// STEP_NEEDED (Begin reads it into a *StepNeededError).
	Data json.RawMessage
	// Err is the underlying cause, when there is one (network, JSON).
	Err error
}

// Error returns "qauth: <code> (<status>): <message>".
func (e *Error) Error() string {
	s := fmt.Sprintf("qauth: %s (%d): %s", e.Code, e.Status, e.Message)
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is an *Error with the same Code, so
// errors.Is(err, qauth.ErrTokenExpired) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code != "" && t.Code == e.Code
}

// Codes of qAuth's answers (the server's universal codes) and of tokens this
// backend refused. Token refusals are status 401, except CodeKeysUnavailable
// (503: the issuer's discovery or keys could not be fetched).
const (
	CodeBadRequest   = "BAD_REQUEST"
	CodeUnauthorized = "UNAUTHORIZED"
	CodeForbidden    = "FORBIDDEN"
	CodeNotFound     = "RESOURCE_NOT_FOUND"
	CodeConflict     = "CONFLICT"
	CodeValidation   = "VALIDATION_ERROR"
	CodeRateLimited  = "RATE_LIMITED"
	// CodeStepNeeded: the person's sign-in isn't fresh enough to add a
	// passkey (403; AppPasskeys.Begin answers a *StepNeededError).
	CodeStepNeeded  = "STEP_NEEDED"
	CodeBadResponse = "BAD_RESPONSE"
	// CodeUnexpectedRedirect: qAuth answered a redirect; the SDK never follows one.
	CodeUnexpectedRedirect = "UNEXPECTED_REDIRECT"
	// CodeUntrustedAPI: the issuer's discovery names a qAuth API host that
	// isn't trusted (DefaultTrustedAPIHosts / WithTrustedAPIHosts).
	CodeUntrustedAPI = "UNTRUSTED_API"
	// CodeInvalidArgument: an id was empty, "." or ".."; nothing was sent (Status 0).
	CodeInvalidArgument = "INVALID_ARGUMENT"
	// CodeUnavailable: qAuth could not be reached (Status 0).
	CodeUnavailable    = "UNAVAILABLE"
	CodeTokenMissing   = "TOKEN_MISSING"
	CodeTokenMalformed = "TOKEN_MALFORMED"
	CodeTokenExpired   = "TOKEN_EXPIRED"
	CodeNotYetValid    = "TOKEN_NOT_YET_VALID"
	CodeWrongIssuer    = "WRONG_ISSUER"
	CodeWrongClient    = "WRONG_CLIENT"
	CodeWrongAudience  = "WRONG_AUDIENCE"
	CodeBadSignature   = "BAD_SIGNATURE"
	// CodeNotAccessToken: an ID token (or another kind of JWT) sent as an access token.
	CodeNotAccessToken = "NOT_ACCESS_TOKEN"
	// CodeKeysUnavailable: the issuer's discovery or keys could not be fetched.
	CodeKeysUnavailable = "KEYS_UNAVAILABLE"
)

// Sentinels for errors.Is. They match any *Error with the same Code.
var (
	ErrUnauthorized       = &Error{Code: CodeUnauthorized}
	ErrForbidden          = &Error{Code: CodeForbidden}
	ErrNotFound           = &Error{Code: CodeNotFound}
	ErrConflict           = &Error{Code: CodeConflict}
	ErrValidation         = &Error{Code: CodeValidation}
	ErrRateLimited        = &Error{Code: CodeRateLimited}
	ErrStepNeeded         = &Error{Code: CodeStepNeeded}
	ErrUnavailable        = &Error{Code: CodeUnavailable}
	ErrUnexpectedRedirect = &Error{Code: CodeUnexpectedRedirect}
	ErrInvalidArgument    = &Error{Code: CodeInvalidArgument}
	ErrTokenMissing       = &Error{Code: CodeTokenMissing}
	ErrTokenMalformed     = &Error{Code: CodeTokenMalformed}
	ErrTokenExpired       = &Error{Code: CodeTokenExpired}
	ErrNotYetValid        = &Error{Code: CodeNotYetValid}
	ErrWrongIssuer        = &Error{Code: CodeWrongIssuer}
	ErrWrongClient        = &Error{Code: CodeWrongClient}
	ErrWrongAudience      = &Error{Code: CodeWrongAudience}
	ErrBadSignature       = &Error{Code: CodeBadSignature}
	ErrNotAccessToken     = &Error{Code: CodeNotAccessToken}
	ErrKeysUnavailable    = &Error{Code: CodeKeysUnavailable}
)

// StatusOf returns the HTTP status of err when it is an *Error, else 0.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func tokenErr(code, msg string, cause error) *Error {
	st := http.StatusUnauthorized
	if code == CodeKeysUnavailable {
		st = http.StatusServiceUnavailable
	}
	return &Error{Status: st, Code: code, Message: msg, Err: cause}
}

// parseRetryAfter reads Retry-After: delta-seconds or an HTTP date.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := at.Sub(now); d > 0 {
			return d.Round(time.Second)
		}
	}
	return 0
}
