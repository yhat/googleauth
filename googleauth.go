// Package googleauth allows web servers to authenticate using Google OpenID through OAuth2.
package googleauth

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/sessions"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	emailURL    = "https://www.googleapis.com/oauth2/v3/userinfo"
	emailScopes = []string{"email", "openid", "profile"}
)

func init() {
	gob.Register(&Account{})
}

type Account struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FamilyName    string `json:"family_name"`
	Gender        string `json:"gender"`
	GivenName     string `json:"given_name"`
	Domain        string `json:"hd"`
	Locale        string `json:"locale"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Profile       string `json:"profile"`
	Sub           string `json:"sub"`
}

type Auth struct {
	// AccountCallback is called when a client attempts to log into the app.
	// It should return nil if the login is successful and a handler to use
	// to display an error otherwise.
	// If nil, anyone who logs in through the Google will be unrestricted.
	AccountCallback func(account Account) (failed http.Handler)

	// Success is used when the user first successfully authenticates.
	// If nil, the user is redirected to '/'
	Success http.Handler

	config       *oauth2.Config
	sessionStore sessions.Store
}

func New(clientID, clientSecret, redirectURL string, store sessions.Store) *Auth {
	return &Auth{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       emailScopes,
			Endpoint:     google.Endpoint,
		},
		sessionStore: store,
	}
}

func (auth *Auth) getAccount(oauth2Code string) (Account, error) {

	// create a context to clean up the generated http.Client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	account := Account{}

	tok, err := auth.config.Exchange(ctx, oauth2Code)
	if err != nil {
		return account, fmt.Errorf("failed to authorize user: %v", err)
	}

	resp, err := auth.config.Client(ctx, tok).Get(emailURL)
	if err != nil {
		return account, fmt.Errorf("could not make GET request to google api: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return account, fmt.Errorf("failed to read response body from google: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return account, fmt.Errorf("bad response from google %s: %s", resp.Status, body)
	}

	if err := json.Unmarshal(body, &account); err != nil {
		return Account{}, fmt.Errorf("failed to parse body %v: %s", err, body)
	}

	return account, nil
}

// HandleRedirect handles the OAuth2 redirect from Google and attempts to
// associate a Google account with the client's session.
func (auth *Auth) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "you're not a google redirect", http.StatusBadRequest)
		return
	}
	account, err := auth.getAccount(code)
	if err != nil {
		log.Printf("could not authorize user: %v", err)
		http.Error(w, "authorization failed", http.StatusInternalServerError)
		return
	}

	if auth.AccountCallback != nil {
		if errHandler := auth.AccountCallback(account); errHandler != nil {
			errHandler.ServeHTTP(w, r)
			return
		}
	}

	// ignore error from decoding a session
	session, _ := auth.sessionStore.Get(r, "GoogleUserInfo")
	session.Values["account"] = account
	if err = auth.sessionStore.Save(r, w, session); err != nil {
		log.Println("could not save session store: %v", err)
		http.Error(w, "authorization failed", http.StatusInternalServerError)
		return
	}

	if auth.Success != nil {
		auth.Success.ServeHTTP(w, r)
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// HandleLogin makes a OAuth2 redirect to Google to attempt a login.
func (auth *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	redirectURL := auth.config.AuthCodeURL("state")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// Account returns the Google account associated with a Request.
// If there is not one, ok will be false.
func (auth *Auth) Account(r *http.Request) (account Account, ok bool) {
	session, _ := auth.sessionStore.Get(r, "GoogleUserInfo")
	acc, ok := session.Values["account"].(*Account)
	if !ok {
		return Account{}, false
	}
	return *acc, true
}

// Restrict returns a handler which prevents users who are logged in from
// accessing the authorized handler. If a user is not logged in,
// the request is passed to unauthorized.
//
// If unauthorized is nil, a simple 401 error is displayed.
func (auth *Auth) Restrict(authorized, unauthorized http.Handler) http.Handler {
	hf := func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.Account(r); ok {
			authorized.ServeHTTP(w, r)
			return
		}
		if unauthorized != nil {
			unauthorized.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
	return http.HandlerFunc(hf)
}

// Logout dissociates an account with a user session.
func (a *Auth) Logout(r *http.Request, w http.ResponseWriter) error {
	session, _ := a.sessionStore.Get(r, "GoogleUserInfo")
	session.Values["account"] = nil
	return a.sessionStore.Save(r, w, session)
}
