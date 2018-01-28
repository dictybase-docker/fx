package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/dgrijalva/jwt-go.v3"

	"github.com/nuclio/nuclio-sdk"
)

var jwtKey string
var validator *JWTValidator
var (
	signMethod           = "RSA"
	errMissingKey        = errors.New("jwt validation key is not provided: fix and redeploy the function")
	errInvalidSignMethod = errors.New("invalid signing method provided: fix and redeploy the function")
	isInvalidSignMethod  = false
)

func main() {
}

func init() {
	jwtKey = os.Getenv("JWT_VALIDATION_KEY")
	if len(os.Getenv("JWT_SIGN_METHOD")) > 0 {
		signMethod = os.Getenv("JWT_SIGN_METHOD")
	}
	opt := Options{
		ValidationKeyGetter: GetKey,
		Debug:               true,
	}
	switch signMethod {
	case "ECDSA":
		opt.SigningMethod = jwt.SigningMethodES512
	case "RSA":
		opt.SigningMethod = jwt.SigningMethodRS512
	case "HMAC":
		opt.SigningMethod = jwt.SigningMethodHS512
	default:
		isInvalidSignMethod = true
	}
	validator = NewValidator(opt)
}

func Handler(ctx *nuclio.Context, event nuclio.Event) (interface{}, error) {
	if len(jwtKey) == 0 {
		return nuclio.Response{
			StatusCode:  http.StatusInternalServerError,
			ContentType: "text/plain",
			Body:        []byte(errMissingKey.Error()),
		}, errMissingKey
	}
	if isInvalidSignMethod {
		return nuclio.Response{
			StatusCode:  http.StatusInternalServerError,
			ContentType: "text/plain",
			Body:        []byte(errInvalidSignMethod.Error()),
		}, errInvalidSignMethod
	}
	validator.Context = ctx
	if err := validator.CheckJWT(event); err != nil {
		return nuclio.Response{
			StatusCode:  http.StatusUnauthorized,
			ContentType: "text/plain",
			Body:        []byte(err.Error()),
		}, err
	}
	return nuclio.Response{
		StatusCode:  http.StatusOK,
		ContentType: "text/plain",
		Body:        []byte("token validation successful"),
	}, nil

}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(event nuclio.Event) (string, error) {
	authHeader := event.GetHeaderString("Authorization")
	if len(authHeader) == 0 {
		return "", errors.New("no token in Authorization header")
	}
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}
	return authHeaderParts[1], nil
}

// FromFirst returns a function that runs multiple token extractors and takes the
// first token it finds
func FromFirst(extractors ...TokenExtractor) TokenExtractor {
	return func(event nuclio.Event) (string, error) {
		for _, ex := range extractors {
			token, err := ex(event)
			if err != nil {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
		return "", errors.New("no token is extracted from any of the extractors")
	}
}

// The function that will return the Key to validate the JWT.
// It can be either a shared secret or a public key.
func GetKey(token *jwt.Token) (interface{}, error) {
	return []byte(jwtKey), nil
}

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error.  An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed.  In the case where a token is simply not present, this should not
// be treated as an error.  An empty string should be returned in that case.
type TokenExtractor func(nuclio.Event) (string, error)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// The name of the property in the request where the user information
	// from the JWT will be stored.
	// Default value: "user"
	UserProperty string
	// A function that extracts the token from the request
	// Default: FromAuthHeader (i.e., from Authorization header as bearer token)
	Extractor TokenExtractor
	// Debug flag turns on debugging output
	// Default: false
	Debug bool
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod
	// Per Request context, part of nuclio-sdk
	Context *nuclio.Context
}

type JWTValidator struct {
	Options
}

// New constructs a new Secure instance with supplied options.
func NewValidator(option Options) *JWTValidator {
	if option.UserProperty == "" {
		option.UserProperty = "user"
	}
	if option.Extractor == nil {
		option.Extractor = FromAuthHeader
	}
	return &JWTValidator{option}
}

func (v *JWTValidator) logf(format string, args ...interface{}) {
	if v.Debug {
		v.Context.Logger.Debug(format, args)
	}
}

func (v *JWTValidator) CheckJWT(event nuclio.Event) error {
	if !v.EnableAuthOnOptions {
		if event.GetMethod() == "OPTIONS" {
			return nil
		}
	}

	// Use the specified token extractor to extract a token from the request
	token, err := v.Extractor(event)

	// If debugging is turned on, log the outcome
	if err != nil {
		v.logf("error extracting JWT: %v", err)
		return err
	}
	// If the token is empty...
	if token == "" {
		// If we get here, the required token is missing
		errorMsg := "Required authorization token not found"
		v.logf(errorMsg)
		return errors.New(errorMsg)
	}
	v.logf("Token extracted: %s", token)

	// Now parse the token
	parsedToken, err := jwt.Parse(token, v.ValidationKeyGetter)
	// Check if there was an error in parsing...
	if err != nil {
		v.logf("Error parsing token: %v", err)
		return err
	}

	if v.SigningMethod != nil && v.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			v.Options.SigningMethod.Alg(),
			parsedToken.Header["alg"])
		v.logf("Error validating token algorithm: %s", message)
		return fmt.Errorf("Error validating token algorithm: %s", message)
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		v.logf("Parsed token is invalid")
		return fmt.Errorf("Parsed token is invalid %s", token)
	}
	v.logf("JWT: %v", parsedToken)

	// Now check the claims
	claims, ok := parsedToken.Claims.(jwt.StandardClaims)
	if !ok {
		v.logf("%s", "unable to get the claims")
		return fmt.Errorf("%s", "unable to get the claims")
	}
	if err := claims.Valid(); err != nil {
		v.logf("Invalid claims %s", err)
		return fmt.Errorf("Invalid claims %s", err)
	}

	// If we get here, everything worked
	return nil
}

// FromParameter returns a function that extracts the token from the specified
// query string parameter
//func FromParameter(param string) TokenExtractor {
//return func(event *nuclio.Event) (string, error) {
//return r.URL.Query().Get(param), nil
//}
//}
