package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// userinfo serves a provider's userinfo document.
func userinfo(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func googleAt(url string) provider {
	p := providers["google"]
	p.userinfoURL = url
	return p
}

func TestGoogleVerifiedEmailIsAccepted(t *testing.T) {
	p := googleAt(userinfo(t, `{"email":"a@example.com","verified_email":true}`))
	e, err := fetchEmail(context.Background(), "google", p, "tok")
	if err != nil || e != "a@example.com" {
		t.Fatalf("got %q, %v; want the verified address", e, err)
	}
}

// The email is what links a login to an existing account, so an address Google has
// not verified must never sign anyone in.
func TestGoogleUnverifiedEmailIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"email":"victim@example.com","verified_email":false}`,
		`{"email":"victim@example.com"}`,
		`{"email":"victim@example.com","verified_email":"true"}`,
	} {
		p := googleAt(userinfo(t, body))
		e, err := fetchEmail(context.Background(), "google", p, "tok")
		if !errors.Is(err, errUnverified) || e != "" {
			t.Errorf("%s: got %q, %v; want errUnverified", body, e, err)
		}
	}
}

func TestAfterLoginOnlyAllowsALocalPath(t *testing.T) {
	cases := map[string]string{
		"":                     "/dashboard",
		"/workspaces":          "/workspaces",
		"/en/workspaces?x=1":   "/en/workspaces?x=1",
		"//evil.example":       "/dashboard",
		`/\evil.example`:       "/dashboard",
		"https://evil.example": "/dashboard",
		"workspaces":           "/dashboard",
	}
	for in, want := range cases {
		t.Setenv("OAUTH_AFTER_LOGIN", in)
		if got := afterLogin(); got != want {
			t.Errorf("OAUTH_AFTER_LOGIN=%q: got %q, want %q", in, got, want)
		}
	}
}

func TestCallbackClearsTheStateCookieAndRejectsAMismatch(t *testing.T) {
	h := callbackHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oauth/google/callback?state=b&code=x", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "a"})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a state mismatch", rec.Code)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "oauth_state" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the state cookie was not cleared")
	}
}
