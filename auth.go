package auth

/*
  This package is to determine a consumers authentication and authorisation to a handler

  ```
  [{
      "user": "username",
      "pass": "password",
      "auth": [
          "func1",
          "func2"
      ]
  }]
  ```
*/

import (
	crypto "crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	guuid "github.com/google/uuid"
)

const (
	// RFC 2617 defines two initial quality of protection values: "auth" indicating
	// authentication, and "auth-int" indicating authentication with message
	// integrity protection

	// QOPAuth defines the type for auth digest
	QOPAuth string = "auth"
	// QOPAuthInt defines the type for auth-int digest
	QOPAuthInt string = "auth-int"
	// ncStart defines the starting number for a nonce count
	ncStart string = "00000001"
)

// NonceTTL defines to the time of a nonce to live, a var instead of const so that
// it can be overwritten
var NonceTTL time.Duration = 30 * time.Second

// digestAuth is a storage object
type digestAuth struct {
	HA1    string `json:"ha1"`
	NC     string `json:"nc"`
	CNonce string `json:"cnonse"`
}

// UnmarshalBinary converts bytes to storage object
func (d *digestAuth) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}

// MarshalBinary converts storage object to bytes
func (d *digestAuth) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

// Auth holds our authetication and authorisation
type Auth struct {
	app            string
	storage        RedisClient
	authentication map[string]string   // map[testuser]testpass
	authorisation  map[string][]string // map[testuser][]string{"func1","func2"}
}

// New instantiates an Auth instance
func New(app string, storage RedisClient, auth []byte) (*Auth, error) {
	a := &Auth{
		app:     app,
		storage: storage,
	}

	err := json.Unmarshal(auth, a)

	return a, err
}

// UnmarshalJSON provides custom unmarshal of JSON
func (a *Auth) UnmarshalJSON(data []byte) error {
	var authentication []struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}

	if err := json.Unmarshal(data, &authentication); err != nil {
		return err
	}

	a.authentication = make(map[string]string)
	if len(authentication) > 0 {
		for _, val := range authentication {
			(a.authentication)[val.User] = val.Pass
		}
	}

	var authorisation []struct {
		User string   `json:"user"`
		Auth []string `json:"auth"`
	}

	if err := json.Unmarshal(data, &authorisation); err != nil {
		return err
	}

	a.authorisation = make(map[string][]string)
	if len(authorisation) > 0 {
		for _, val := range authorisation {
			(a.authorisation)[val.User] = val.Auth
		}
	}

	return nil
}

// Basic performs basic authetication
func (a *Auth) Basic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()

		// checking authentication
		if p, ok := a.authentication[user]; ok {
			if p == pass {
				// check authorisation
				if permissions, ok := a.authorisation[user]; ok {
					if len(permissions) > 0 {
						for _, permission := range permissions {
							if matched, _ := regexp.MatchString(fmt.Sprintf("^%s$", strings.Replace(permission, "*", "[a-zA-Z0-9_~-]{1,}", -1)), r.URL.Path[1:]); matched {
								h.ServeHTTP(w, r)
								return
							}
						}
					}
				}
				// fail authorisation
				http.Error(w, "", http.StatusForbidden)
				return
			}
		}
		// fail authentication
		http.Error(w, "", http.StatusUnauthorized)
		return
	})
}

var md5 = func(str string) string {
	return fmt.Sprintf("%x", crypto.Sum([]byte(str)))
}

// Digest performs digest authetication
func (a *Auth) Digest(qop string, h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var newnonce string
		headers := strings.Split(strings.Replace(r.Header.Get("Authorization"), "Digest", "", 1), ",")

		if len(headers) == 0 {
			// fail authentication
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var auth = make(map[string]string, len(headers))
		for _, header := range headers {
			p := strings.Split(header, "=")
			if len(p) == 2 {
				// strip both whitespace and double quotes
				auth[strings.TrimSpace(p[0])] = strings.Trim(strings.TrimSpace(p[1]), "\"")
			}
		}
		if len(auth) == 0 {
			// fail authentication
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// lets ensure we have a username
		username, ok := auth["username"]
		if !ok {
			// fail authentication
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// does the user have permission?
		password, ok := a.authentication[username]
		if !ok {
			// fail authentication
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var stale = false
		//now we have to validate the nonce
		d, err := storageGetAndDelete(a.storage, auth["nonce"])
		if err == nil {
			if d != "" {
				var digest digestAuth
				if err = json.Unmarshal([]byte(d), &digest); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if qop == auth["qop"] && digest.CNonce != auth["cnonce"] && digest.NC == auth["nc"] {
					switch qop {
					case QOPAuthInt:
						// in order to validate the authentication, the given response (consumer) should match our generated
						// 1) HA1 = md5(username:realm:password)
						// 2) HA2 = md5(method:URI:md5(body))
						// 3) response = md5(HA1:Nonce:NonceCount:ClientNonce:qop:HA2)
						b, err := ioutil.ReadAll(r.Body)
						if err != nil {
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						r.Body.Close()

						if md5(strings.Join([]string{
							digest.HA1,
							auth["nonce"],
							auth["nc"],
							auth["cnonce"],
							qop,
							md5(strings.Join([]string{
								r.Method,
								r.URL.RequestURI(),
								md5(string(b)),
							}, ":")),
						}, ":")) == auth["response"] {
							// we pass authentication and move on to authorisation
							goto AUTHORISE
						}

					default:
						// in order to validate the authentication, the given response (consumer) should match our generated
						// 1) HA1 = md5(username:realm:password)
						// 2) HA2 = md5(method:URI)
						// 3) response = md5(HA1:Nonce:NonceCount:ClientNonce:qop:HA2)
						if md5(strings.Join([]string{
							digest.HA1,
							auth["nonce"],
							auth["nc"],
							auth["cnonce"],
							qop,
							md5(strings.Join([]string{
								r.Method,
								r.URL.RequestURI(),
							}, ":")),
						}, ":")) == auth["response"] {
							// we pass authentication and move on to authorisation
							goto AUTHORISE
						}
					}
				}
			} else {
				// mark as stale nonce
				stale = true
			}
		}

		// a nonce is not provided so we return unauthorised but with a generated nonce for subsequent request
		newnonce = guuid.New().String()
		// this can be done concurrent with return, we use the nonce as the key and the client ID as the value
		go func(nonce string, obj interface{}) {
			storageSet(a.storage, nonce, obj, NonceTTL)
			return
		}(newnonce, &digestAuth{
			HA1: md5(strings.Join([]string{
				username,
				a.app,
				password,
			}, ":")),
			NC: ncStart,
		})

		w.Header().Set("WWW-Authenticate", func() string {
			var ret = fmt.Sprintf("Digest realm=\"%s\", nonce=\"%s\", qop=\"%s\", algorithm=\"MD5\", nc=\"%s\"", a.app, newnonce, qop, ncStart)
			if stale {
				strings.Join([]string{
					ret,
					"stale=TRUE",
				}, " ")
			}
			return ret
		}())
		// fail authentication
		w.WriteHeader(http.StatusUnauthorized)
		return

	AUTHORISE:
		if len(headers) > 0 {
			for _, header := range headers {
				p := strings.Split(header, "=")
				if strings.TrimSpace(p[0]) == "username" {
					if val, ok := a.authorisation[strings.Trim(strings.TrimSpace(p[1]), "\"")]; ok {
						if len(val) > 0 {
							for _, perm := range val {
								if matched, _ := regexp.MatchString(fmt.Sprintf("^%s$", strings.Replace(perm, "*", "[a-zA-Z0-9_~-]{1,}", -1)), r.URL.Path[1:]); matched {
									// we add the nonce to the responsewriter for subsequent requests
									// we have to increment the nonce count
									nc, err := strconv.Atoi(auth["nc"])
									if err != nil {
										w.WriteHeader(http.StatusBadRequest)
										return
									}
									nc++

									go func(nonce string, obj interface{}) {
										storageSet(a.storage, nonce, obj, NonceTTL)
										return
									}(auth["nonce"], &digestAuth{
										HA1: md5(strings.Join([]string{
											username,
											a.app,
											password,
										}, ":")),
										NC:     fmt.Sprintf("%08d", nc),
										CNonce: auth["cnonce"],
									})
									w.Header().Set("WWW-Authenticate", fmt.Sprintf("Digest realm=\"%s\", nonce=\"%s\", qop=\"%s\", algorithm=\"MD5\", nc=\"%s\"", a.app, auth["nonce"], qop, fmt.Sprintf("%08d", nc)))

									h.ServeHTTP(w, r)
									return
								}
							}
						}
					}
				}
			}
		}
		// fail authorisation
		w.WriteHeader(http.StatusForbidden)
		return
	})
}
