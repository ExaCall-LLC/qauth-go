// Package qauth is the Go SDK for backends of products that use qAuth for
// sign-in and authorization.
//
// It does four jobs:
//
//   - Verifier checks the access tokens people send to your API, offline:
//     the signature against the issuer's published keys, the issuer, the
//     client the token was issued to, the audience and the times. No call to
//     qAuth per request. Verifier.Middleware wraps a net/http handler.
//   - Client.Permissions and Client.Can ask qAuth what the person may do in
//     one of your apps inside one organization, with a short cache.
//   - Client.ValidateKey checks an API key a customer's system sent to your
//     API, with a short cache; KeyMay says whether it may use a permission.
//   - Client.As (the person, with their access token) and Client.WithKey (an
//     organization's API key) call qAuth's person and organization APIs.
//
// Every refusal is an *Error with the HTTP status, a stable code, a message,
// qAuth's request id and, on 429, how long to wait.
//
// The package never imports qAuth's server code: apps only pull this module
// and go-jose.
package qauth
