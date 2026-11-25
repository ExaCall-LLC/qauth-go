package qauth

import (
	"context"
	"strings"
	"testing"
)

const shopDefinition = `version: 1
api: {id: sdk-shop, name: SDK Shop API}
levels: [Customer]
permissions:
  - {key: order:approve, level: Customer, group: Orders, name: Approve orders}
  - {key: usage:view, level: floating, name: View usage}
roles:
  - {name: Approver, level: Customer, permissions: [order:approve, usage:view]}
apps:
  - {id: web, name: SDK Shop, type: web, redirects: ["http://localhost:5173/cb"]}
resources:
  - {type: order, parent: organization, roles: [Approver]}
`

// Against qAuth's real routes: a dry run, an apply, the same file again
// (nothing to do), another api id with the same key (refused), an invalid
// file (problems), and an unknown key (an *Error, 401).
func TestSetupClientLive(t *testing.T) {
	seed := liveSeed(t)
	c, err := NewSetupClient(seed.BaseURL, seed.SetupKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req := SetupRequest{Content: shopDefinition, Source: "github.com/acme/shop", Path: "qauth.app.yaml", Commit: "abc1234"}
	res, err := c.Plan(ctx, req)
	if err != nil || res.Result != SetupDryRun || res.Plan.Added == 0 || !strings.Contains(res.Text, "Plan for \"SDK Shop API\" (sdk-shop)") || !res.OK() {
		t.Fatalf("plan = %+v %v", res, err)
	}
	if res, err = c.Apply(ctx, req); err != nil || res.Result != SetupApplied || res.Run == 0 {
		t.Fatalf("apply = %+v %v", res, err)
	}
	if res, err = c.Apply(ctx, req); err != nil || res.Result != SetupNoChanges || !res.OK() {
		t.Fatalf("again = %+v %v", res, err)
	}
	other := strings.Replace(shopDefinition, "id: sdk-shop", "id: sdk-other", 1)
	if res, err = c.Apply(ctx, SetupRequest{Content: other}); err != nil || res.Result != SetupRefused || res.Status != 409 || res.OK() {
		t.Fatalf("other id = %+v %v", res, err)
	}
	if res, err = c.Plan(ctx, SetupRequest{Content: "version: 1\napi: {id: sdk-shop}\nlevel: []\n"}); err != nil || res.Status != 422 || len(res.Problems) == 0 {
		t.Fatalf("invalid = %+v %v", res, err)
	}
	bad, _ := NewSetupClient(seed.BaseURL, "qsk_"+strings.Repeat("z", 40), nil)
	if _, err := bad.Plan(ctx, req); StatusOf(err) != 401 {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := NewSetupClient("http://qauth.example.test", seed.SetupKey, nil); err == nil {
		t.Fatal("plain http to a remote host accepted")
	}
	if _, err := NewSetupClient(seed.BaseURL, "qak_x", nil); err == nil {
		t.Fatal("an API key accepted as a setup key")
	}
}
