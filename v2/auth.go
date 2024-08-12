package auth

/*
  This package is to determine a consumers authentication and authorisation to a handler

  Firstly, define the roles and the access to which applies to each
  ```
  {
    "tooladmin": [
      "api/*",
    ],
    "toolops": [
      "api/ops/task1",
	  "api/ops/task2",
	  "api/ops/task3"
    ]
  }
  ```

  Secondly, the users for which roles they are assigned to
  ```
  [{
      "user": "username",
      "pass": "password",
      "group": [
          "tooladmin",
          "toolops"
      ],
      "rate": {
        "burst": 1,
        "limit": 300, // this is the per second restrictions
      }
  }]
  ```
*/

import (
	"bytes"
	"crypto/hmac"
	crypto "crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LK4D4/trylock"
	guuid "github.com/google/uuid"
	"golang.org/x/time/rate"
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

const permissionsReg string = "[a-zA-Z0-9/+=%@_~:.-]{1,}"

// NonceTTL defines to the time of a nonce to live, a var instead of const so that
// it can be overwritten
var NonceTTL time.Duration = 30 * time.Second

// lock is used to allow concurrency but the auth needs to be locked for certain events
var lock = &trylock.Mutex{}

// digestAuth is a storage object
type digestAuth struct {
	HA1    string `json:"ha1"`
	NC     string `json:"nc"`
	CNonce string `json:"cnonse"`
}

// Role defines the roles structure
type Role struct {
	ID   string   `json:"id"`
	Auth []string `json:"auth"`
}

// Authentication defines the auth structure
type Authentication struct {
	User  string             `json:"user,omitempty"`
	Token string             `json:"token,omitempty"`
	Pass  string             `json:"pass,omitempty"`
	Roles []string           `json:"roles"`
	Rate  AuthenticationRate `json:"rate,omitempty"`
}

// AuthenticationRate defines the auth rate structure
type AuthenticationRate struct {
	Burst rate.Limit `json:"burst"`
	Limit int        `json:"limit"`
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

	// rate limiter
	mu sync.Mutex
	li *rate.Limiter
}

var roles = map[string][]string{}

// New instantiates an Auth instance
func New(app string, storage RedisClient, r interface{}, auth interface{}) (*Auth, error) {
	a := &Auth{
		app:     app,
		storage: storage,
	}

	switch r.(type) {
	case []Role:
		for _, v := range r.([]Role) {
			roles[v.ID] = v.Auth
		}
	case []uint8:
		if err := json.Unmarshal(r.([]uint8), &roles); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Unexpected interface type for roles")
	}

	switch auth.(type) {
	case []Authentication:
		b, err := json.Marshal(auth.([]Authentication))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, a); err != nil {
			return nil, err
		}
	case []uint8:
		if err := json.Unmarshal(auth.([]uint8), a); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Unexpected interface type for auth")
	}

	return a, nil
}

// UnmarshalJSON provides custom unmarshal of JSON
func (a *Auth) UnmarshalJSON(data []byte) error {
	var authentication []Authentication
	if err := json.Unmarshal(data, &authentication); err != nil {
		return err
	}

	a.authentication = make(map[string]string, len(authentication))
	a.authorisation = make(map[string][]string)
	if len(authentication) > 0 {
		for _, val := range authentication {
			auths := func(r []string) []string {
				var auths = make(map[string]string)
				for _, role := range val.Roles {
					// do we find the role in the global roles
					if rs, found := roles[role]; found {
						for _, auth := range rs {
							auths[auth] = auth
						}
					}
				}

				a := []string{}
				for v := range auths {
					a = append(a, v)
				}
				return a
			}(val.Roles)

			switch val.User != "" && val.Pass != "" {
			case true:
				(a.authentication)[val.User] = val.Pass
				(a.authorisation)[val.User] = auths

			default:
				(a.authorisation)[val.Token] = auths
			}

			// what about rate limiting, we expect but do not require two attributes
			// because we set defaults (which is a non limit 10000, 10000):
			// - rate.limit
			// - rate.burst
			switch val.Rate.Burst > 0 && val.Rate.Limit > 0 {
			case true:
				a.li = rate.NewLimiter(val.Rate.Burst, val.Rate.Limit)

			default:
				a.li = rate.NewLimiter(10000, 10000)
			}
		}
	}

	return nil
}

// Allow checks whether the auth user has or has not exceeded predefined
// allowance of requests per second
func (a *Auth) Allow() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.li.Allow()
}

// Token performs bearer token authetication
func (a *Auth) Token(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if permissions, ok := a.authorisation[strings.TrimSpace(strings.Replace(r.Header.Get("Authorization"), "Bearer", "", 1))]; ok {
			if len(permissions) > 0 {
				for _, permission := range permissions {
					if matched, _ := regexp.MatchString(fmt.Sprintf("^%s$", strings.Replace(permission, "*", permissionsReg, -1)), r.URL.Path[1:]); matched {
						if !a.Allow() {
							w.WriteHeader(http.StatusTooManyRequests)
							return
						}
						h.ServeHTTP(w, r)
						return
					}
				}
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	})
}

// Basic performs basic authetication
func (a *Auth) Basic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()

		// checking authentication
		if p, ok := a.authentication[user]; ok {

			if p == md5(strings.Join([]string{
				user,
				a.app,
				pass,
			}, ":")) {
				// check authorisation
				if permissions, ok := a.authorisation[user]; ok {
					if len(permissions) > 0 {
						for _, permission := range permissions {
							if matched, _ := regexp.MatchString(fmt.Sprintf("^%s$", strings.Replace(permission, "*", permissionsReg, -1)), r.URL.Path[1:]); matched {
								if !a.Allow() {
									w.WriteHeader(http.StatusTooManyRequests)
									return
								}
								h.ServeHTTP(w, r)
								return
							}
						}
					}
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
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

		authenticated, auth, stale := func() (bool, map[string]string, bool) {
			var auth = make(map[string]string, len(headers))

			if len(headers) == 0 {
				return false, auth, false
			}

			for _, header := range headers {
				p := strings.Split(header, "=")
				if len(p) == 2 {
					// strip both whitespace and double quotes
					auth[strings.TrimSpace(p[0])] = strings.Trim(strings.TrimSpace(p[1]), "\"")
				}
			}
			if len(auth) == 0 {
				return false, auth, false
			}

			// lets ensure we have a username
			username, ok := auth["username"]
			if !ok || username == "" {
				return false, auth, false
			}
			// does the user have permission?
			ha1, ok := a.authentication[username]
			if !ok || ha1 == "" {
				return false, auth, false
			}

			//now we have to validate the nonce
			d, err := storageGetAndDelete(a.storage, auth["nonce"])
			if err != nil || d == "" {
				return false, auth, false
			}

			var digest digestAuth
			if err = json.Unmarshal([]byte(d), &digest); err != nil {
				return false, auth, false
			}

			if qop != auth["qop"] || digest.CNonce == auth["cnonce"] || digest.NC != auth["nc"] {
				return false, auth, true
			}

			switch qop {
			case QOPAuthInt:
				// in order to validate the authentication, the given response (consumer) should match our generated
				// 1) HA1 = md5(username:realm:password)
				// 2) HA2 = md5(method:URI:md5(body))
				// 3) response = md5(HA1:Nonce:NonceCount:ClientNonce:qop:HA2)
				b, err := ioutil.ReadAll(r.Body)
				if err != nil {
					return false, auth, false
				}
				r.Body.Close()

				if md5(strings.Join([]string{
					ha1,
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
					return true, auth, false
				}

			default:
				// in order to validate the authentication, the given response (consumer) should match our generated
				// 1) HA1 = md5(username:realm:password)
				// 2) HA2 = md5(method:URI)
				// 3) response = md5(HA1:Nonce:NonceCount:ClientNonce:qop:HA2)
				if md5(strings.Join([]string{
					ha1,
					auth["nonce"],
					auth["nc"],
					auth["cnonce"],
					qop,
					md5(strings.Join([]string{
						r.Method,
						r.URL.RequestURI(),
					}, ":")),
				}, ":")) == auth["response"] {
					return true, auth, false
				}
			}

			return false, auth, false
		}()

		if !authenticated {
			// this is important to allow the lock to have locked and avoid race condition
			time.Sleep(boff.Duration())

			if lock.TryLock() {
				newnonce = guuid.New().String()
				if err := storageSet(a.storage, newnonce, &digestAuth{
					NC: ncStart,
				}, NonceTTL); err != nil {
					w.WriteHeader(http.StatusFailedDependency)
					return
				}
			} else {
				// this is important to allow the lock to have completeted on any concurrent requests
				time.Sleep(1 * time.Second)
			}

			w.Header().Set("WWW-Authenticate", func() string {
				var ret = fmt.Sprintf("Digest realm=\"%s\", nonce=\"%s\", qop=\"%s\", algorithm=\"MD5\", nc=\"%s\"", a.app, newnonce, qop, ncStart)
				if stale {
					strings.Join([]string{
						ret,
						fmt.Sprintf("stale=%v", stale == true),
					}, " ")
				}
				return ret
			}())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !func() bool {
			for _, header := range headers {
				p := strings.Split(header, "=")
				if strings.TrimSpace(p[0]) == "username" {
					if val, ok := a.authorisation[strings.Trim(strings.TrimSpace(p[1]), "\"")]; ok {
						if len(val) > 0 {
							for _, perm := range val {
								if matched, _ := regexp.MatchString(fmt.Sprintf("^%s$", strings.Replace(perm, "*", permissionsReg, -1)), r.URL.Path[1:]); matched {
									return true
								}
							}
						}
					}
				}
			}

			return false

		}() {
			// fail authorisation
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// we add the nonce to the responsewriter for subsequent requests
		// we have to increment the nonce count
		nc, _ := strconv.Atoi(auth["nc"])
		nc++

		if err := storageSet(a.storage, auth["nonce"], &digestAuth{
			NC:     fmt.Sprintf("%08d", nc),
			CNonce: auth["cnonce"],
		}, NonceTTL); err != nil {
			w.WriteHeader(http.StatusFailedDependency)
			return
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Digest realm=\"%s\", nonce=\"%s\", qop=\"%s\", algorithm=\"MD5\", nc=\"%s\"", a.app, auth["nonce"], qop, fmt.Sprintf("%08d", nc)))

		if !a.Allow() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
		return
	})
}

// HMAC performs a more secure authetication
func (a *Auth) HMAC(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.authentication[r.Header.Get("Auth-Token")]; !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Header.Get("Auth-Hmac") != func(secret string) string {
			b, _ := ioutil.ReadAll(r.Body)
			r.Body = ioutil.NopCloser(bytes.NewReader(b))

			h := hmac.New(sha256.New, []byte(secret))
			h.Write(b)
			return hex.EncodeToString(h.Sum(nil))
		}(a.authentication[r.Header.Get("Auth-Token")]) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// does this token have access to the route
		// check authorisation
		if permissions, ok := a.authorisation[r.Header.Get("Auth-Token")]; ok {
			if len(permissions) > 0 {
				for _, permission := range permissions {
					if matched, _ := regexp.MatchString(fmt.Sprintf("^%s$", strings.Replace(permission, "*", permissionsReg, -1)), r.URL.Path[1:]); matched {
						if !a.Allow() {
							w.WriteHeader(http.StatusTooManyRequests)
							return
						}
						h.ServeHTTP(w, r)
						return
					}
				}
			}
		}

		w.WriteHeader(http.StatusForbidden)
		return
	})
}
