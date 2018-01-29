package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"

	"golang.org/x/oauth2"

	"github.com/dictyBase/apihelpers/aphcollection"
	"github.com/nuclio/nuclio-sdk"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

var (
	googleSecret     string
	fbSecret         string
	linkedInSecret   string
	orcidSecret      string
	ghSecret         string
	jwtKey           *rsa.PrivateKey
	missingPrvKeyFmt string   = "client secret of provider %s is missing"
	providerErrFmt   string   = "unable to authorize with %s"
	allowedProviders []string = []string{"google", "facebook", "linkedin"}
	reqParams        []string = []string{"client_id", "scopes", "redirect_url", "state", "code"}
	errMissingKey    error
	errParsingKey    error
	googlePath       = "https://www.googleapis.com/userinfo/v2/me"
	facebookPath     = "https://graph.facebook.com/v2.5/me?fields=name,email"
	linkedInPath     = "https://api.linkedin.com/v1/people/~:(first-name,last-name,email-address)?format=json"
)

type OauthConfig struct {
	State string
	Code  string
	*oauth2.Config
}

type GoogleUser struct {
	FamilyName    string `json:"family_name"`
	Name          string `json:"name"`
	Gender        string `json:"gender"`
	Email         string `json:"email"`
	GivenName     string `json:"given_name"`
	Id            string `json:"id"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

type FacebookUser struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type LinkedInUser struct {
	FirstName                  string `json:"firstName"`
	Headline                   string `json:"headline"`
	Id                         string `json:"id"`
	LastName                   string `json:"lastName"`
	SiteStandardProfileRequest struct {
		URL string `json:"url"`
	} `json:"siteStandardProfileRequest"`
	EmailAddress string `json:"emailAddress"`
}

type NormalizedUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Id    string `json:"id"`
}

type AuthUser struct {
	Token string          `json:"token"`
	User  *NormalizedUser `json:"user"`
}

func main() {
}

func init() {
	if len(os.Getenv("JWT_SIGN_KEY")) == 0 {
		errMissingKey = errors.New("jwt sign key is not provided: fix and redeploy the function")
	} else {
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(os.Getenv("JWT_SIGN_KEY")))
		if err != nil {
			errParsingKey = err
		} else {
			jwtKey = key
		}
	}
	googleSecret = os.Getenv("GOOGLE_SECRET_KEY")
	fbSecret = os.Getenv("FACEBOOK_SECRET_KEY")
	linkedInSecret = os.Getenv("LINKEDIN_SECRET_KEY")
	orcidSecret = os.Getenv("ORCID_SECRET_KEY")
}

func serverErrorResponse(err string) nuclio.Response {
	return nuclio.Response{
		StatusCode:  http.StatusInternalServerError,
		ContentType: "text/plain",
		Body:        []byte(err),
	}
}

func badRequestResponse(err string) nuclio.Response {
	return nuclio.Response{
		StatusCode:  http.StatusBadRequest,
		ContentType: "text/plain",
		Body:        []byte(err),
	}
}

func successfullResponse(msg []byte) nuclio.Response {
	return nuclio.Response{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Body:        msg,
	}
}

func Handler(ctx *nuclio.Context, event nuclio.Event) (interface{}, error) {
	// Check for JWT signing key
	if errMissingKey != nil {
		return serverErrorResponse(errMissingKey.Error()), errMissingKey
	}
	if errParsingKey != nil {
		return serverErrorResponse(errParsingKey.Error()), errParsingKey
	}
	// Check for supported providers
	pathParts := strings.Split(event.GetPath(), "/")
	if len(pathParts) > 2 {
		msg := fmt.Sprintf("invalid path %s", event.GetPath())
		return badRequestResponse(msg), errors.New(msg)
	}
	if !aphcollection.Contains(allowedProviders, pathParts[1]) {
		msg := fmt.Sprintf("provider %s is not supported", pathParts[1])
		return badRequestResponse(msg), errors.New(msg)
	}
	// Validate query parameters
	for _, p := range reqParams {
		if len(event.GetFieldString(p)) == 0 {
			msg := fmt.Sprintf("required query parameter %s is missing", p)
			return badRequestResponse(msg), errors.New(msg)
		}
	}
	oauthConf := &OauthConfig{
		Config: &oauth2.Config{
			ClientID:    event.GetFieldString("client_id"),
			RedirectURL: event.GetFieldString("redirect_url"),
			Scopes:      strings.Split(event.GetFieldString("scope"), " "),
		},
		State: event.GetFieldString("state"),
		Code:  event.GetFieldString("code"),
	}
	// Process the provider
	errSecretMsg := fmt.Sprintf(missingPrvKeyFmt, pathParts[1])
	errProviderMsg := fmt.Sprintf(providerErrFmt, pathParts[1])
	var user *NormalizedUser
	var err error
	switch pathParts[1] {
	case "google":
		if len(googleSecret) == 0 {
			return serverErrorResponse(errSecretMsg), errors.New(errSecretMsg)
		}
		oauthConf.Config.ClientSecret = googleSecret
		oauthConf.Config.Endpoint = google.Endpoint
		user, err = processGoogle(oauthConf)
	case "facebook":
		if len(fbSecret) == 0 {
			return serverErrorResponse(errSecretMsg), errors.New(errSecretMsg)
		}
		oauthConf.Config.ClientSecret = fbSecret
		oauthConf.Config.Endpoint = facebook.Endpoint
		user, err = processFacebook(oauthConf)
	case "linkedin":
		if len(linkedInSecret) == 0 {
			return serverErrorResponse(errSecretMsg), errors.New(errSecretMsg)
		}
		oauthConf.Config.ClientSecret = linkedInSecret
		oauthConf.Config.Endpoint = linkedin.Endpoint
		user, err = processLinkedIn(oauthConf)
	}

	if err != nil {
		msg := fmt.Sprintf("%s-%s", errProviderMsg, err)
		return serverErrorResponse(msg), errors.New(msg)
	}
	jwt, err := generateJwt(user)
	if err != nil {
		return serverErrorResponse(err.Error()), err
	}
	return successfullResponse(jwt), nil
}

func processGoogle(conf *OauthConfig) (*NormalizedUser, error) {
	nuser := &NormalizedUser{}
	resp, err := processAuth(conf, googlePath)
	if err != nil {
		return nuser, err
	}
	var guser GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&guser); err != nil {
		return nuser, err
	}
	nuser.Name = guser.Name
	nuser.Email = guser.Email
	nuser.Id = guser.Id
	return nuser, nil
}

func processFacebook(conf *OauthConfig) (*NormalizedUser, error) {
	nuser := &NormalizedUser{}
	resp, err := processAuth(conf, facebookPath)
	if err != nil {
		return nuser, err
	}
	var fuser FacebookUser
	if err := json.NewDecoder(resp.Body).Decode(&fuser); err != nil {
		return nuser, err
	}
	nuser.Name = fuser.Name
	nuser.Email = fuser.Email
	nuser.Id = fuser.Id
	return nuser, nil
}

func processLinkedIn(conf *OauthConfig) (*NormalizedUser, error) {
	nuser := &NormalizedUser{}
	resp, err := processAuth(conf, linkedInPath)
	if err != nil {
		return nuser, err
	}
	var luser LinkedInUser
	if err := json.NewDecoder(resp.Body).Decode(&luser); err != nil {
		return nuser, err
	}
	nuser.Name = fmt.Sprintf("%s %s", luser.FirstName, luser.LastName)
	nuser.Email = luser.EmailAddress
	nuser.Id = luser.Id
	return nuser, nil
}

func processAuth(conf *OauthConfig, path string) (*http.Response, error) {
	var resp *http.Response
	token, err := conf.Exchange(oauth2.NoContext, conf.Code)
	if err != nil {
		return resp, err
	}
	return conf.Client(oauth2.NoContext, token).Get(path)
}

func generateJwt(user *NormalizedUser) ([]byte, error) {
	claims := jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * 240).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	token, err := t.SignedString(jwtKey)
	if err != nil {
		return []byte(""), err
	}
	return json.Marshal(&AuthUser{Token: token, User: user})
}
