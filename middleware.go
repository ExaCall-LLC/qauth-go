package qauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ctxIdentity struct{}

// ContextWithIdentity returns ctx carrying id. Middleware does this for you;
// it is exported for your own tests.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxIdentity{}, id)
}

// IdentityFrom returns the verified identity Middleware put on the request's
// context.
func IdentityFrom(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxIdentity{}).(*Identity)
	return id, ok && id != nil
}

// BearerToken returns the token of an "Authorization: Bearer <token>"
// header, or "".
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// Middleware lets a request through only with a valid access token in
// "Authorization: Bearer". The handler reads who it is with IdentityFrom.
//
// A missing or refused token is answered 401 with WWW-Authenticate
// (`Bearer realm="api"`, plus `error="invalid_token",
// error_description="<CODE>"` when a token was sent); 503 when the issuer's
// keys could not be fetched. The body is the JSON error envelope.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return v.middleware(next, false)
}

// OptionalMiddleware is Middleware that also lets requests without a token
// through (with no identity). A token that is sent must be valid.
func (v *Verifier) OptionalMiddleware(next http.Handler) http.Handler {
	return v.middleware(next, true)
}

func (v *Verifier) middleware(next http.Handler, optional bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := BearerToken(r)
		if tok == "" && optional {
			next.ServeHTTP(w, r)
			return
		}
		id, err := v.Verify(r.Context(), tok)
		if err != nil {
			WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithIdentity(r.Context(), id)))
	})
}

// WriteError answers err as JSON {success:false, status, message: code,
// error:{code, message}} with the error's status (502 when qAuth could not
// be reached, 500 for errors that are not an *Error). A 401 gets the
// WWW-Authenticate header of RFC 6750 and the message "Please sign in.";
// Retry-After is passed on when known.
func WriteError(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: "Something went wrong."}
	}
	status := e.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	msg := e.Message
	h := w.Header()
	if status == http.StatusUnauthorized {
		msg = "Please sign in."
		if e.Code == CodeTokenMissing {
			h.Set("WWW-Authenticate", `Bearer realm="api"`) // no error when no token was sent
		} else {
			h.Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="`+e.Code+`"`)
		}
	}
	if e.RetryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(int((e.RetryAfter+time.Second-1)/time.Second)))
	}
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false, "status": status, "message": e.Code,
		"error": map[string]any{"code": e.Code, "message": msg},
	})
}
