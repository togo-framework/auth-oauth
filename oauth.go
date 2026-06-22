// Package oauth adds OAuth2 social login (Google, GitHub, Facebook) to togo auth.
// It registers /api/auth/oauth/{provider} + callback routes; on success it
// find-or-creates the user via auth and issues a togo session. Depends on the
// auth plugin. Install: `togo install togo-framework/auth-oauth`.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/togo-framework/auth"
	"github.com/togo-framework/togo"
)

type provider struct {
	authURL, exchangeURL, userinfoURL, scope, emailField string
}

var providers = map[string]provider{
	"google": {
		authURL: "https://accounts.google.com/o/oauth2/v2/auth",
		exchangeURL: "https://oauth2.googleapis.com/token",
		userinfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
		scope: "openid email profile", emailField: "email",
	},
	"github": {
		authURL: "https://github.com/login/oauth/authorize",
		exchangeURL: "https://github.com/login/oauth/access_token",
		userinfoURL: "https://api.github.com/user", scope: "read:user user:email", emailField: "email",
	},
	"facebook": {
		authURL: "https://www.facebook.com/v18.0/dialog/oauth",
		exchangeURL: "https://graph.facebook.com/v18.0/oauth/access_token",
		userinfoURL: "https://graph.facebook.com/me?fields=email", scope: "email", emailField: "email",
	},
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func init() {
	togo.RegisterProviderFunc("auth-oauth", togo.PriorityLate+20, func(k *togo.Kernel) error {
		svc, ok := auth.FromKernel(k)
		if !ok {
			if k.Log != nil {
				k.Log.Warn("auth-oauth: auth plugin not installed; skipping")
			}
			return nil
		}
		k.Router.Get("/api/auth/oauth/{provider}", redirectHandler())
		k.Router.Get("/api/auth/oauth/{provider}/callback", callbackHandler(svc))
		return nil
	})
}

func clientCreds(name string) (id, secret string) {
	p := "OAUTH_" + strings.ToUpper(name)
	return os.Getenv(p + "_CLIENT_ID"), os.Getenv(p + "_CLIENT_SECRET")
}

func redirectURI(name string) string {
	return strings.TrimRight(os.Getenv("APP_URL"), "/") + "/api/auth/oauth/" + name + "/callback"
}

func redirectHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provider")
		p, ok := providers[name]
		if !ok {
			http.Error(w, "unknown provider", http.StatusNotFound)
			return
		}
		id, _ := clientCreds(name)
		if id == "" {
			http.Error(w, "provider not configured", http.StatusServiceUnavailable)
			return
		}
		state := randHex()
		http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, Path: "/", HttpOnly: true, MaxAge: 600, SameSite: http.SameSiteLaxMode}) //#nosec G124 -- short-lived CSRF state cookie (HttpOnly+SameSite); Secure handled by TLS/proxy in prod
		q := url.Values{
			"client_id":     {id},
			"redirect_uri":  {redirectURI(name)},
			"response_type": {"code"},
			"scope":         {p.scope},
			"state":         {state},
		}
		http.Redirect(w, r, p.authURL+"?"+q.Encode(), http.StatusFound)
	}
}

func callbackHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provider")
		p, ok := providers[name]
		if !ok {
			http.Error(w, "unknown provider", http.StatusNotFound)
			return
		}
		// CSRF: state cookie must match the query.
		c, err := r.Cookie("oauth_state")
		if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
			http.Error(w, "invalid oauth state", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		token, err := exchange(r.Context(), name, p, code)
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}
		email, err := fetchEmail(r.Context(), name, p, token)
		if err != nil || email == "" {
			http.Error(w, "could not resolve email from provider", http.StatusBadGateway)
			return
		}
		id, err := svc.FindOrCreateByEmail(r.Context(), email)
		if err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		if _, err := svc.IssueSession(w, *id); err != nil {
			http.Error(w, "session failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}

func exchange(ctx context.Context, name string, p provider, code string) (string, error) {
	id, secret := clientCreds(name)
	form := url.Values{
		"client_id": {id}, "client_secret": {secret}, "code": {code},
		"redirect_uri": {redirectURI(name)}, "grant_type": {"authorization_code"},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.exchangeURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("no access_token")
	}
	return out.AccessToken, nil
}

func fetchEmail(ctx context.Context, name string, p provider, token string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.userinfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return "", err
	}
	if e, ok := m[p.emailField].(string); ok && e != "" {
		return e, nil
	}
	// GitHub: email may be private — fall back to /user/emails.
	if name == "github" {
		return githubPrimaryEmail(ctx, token)
	}
	return "", fmt.Errorf("email not present")
}

func githubPrimaryEmail(ctx context.Context, token string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	_ = json.Unmarshal(body, &emails)
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no verified primary email")
}

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
