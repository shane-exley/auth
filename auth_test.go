//go:build !release
// +build !release

package auth

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	redis "github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_MarshalBinary(t *testing.T) {
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)
	assert.Nil(t, enc.Encode(&digestAuth{}))
}

func Test_NewAuth_Byte(t *testing.T) {
	var a *Auth
	var err error

	a, err = New("test_app", &MockRedisClient{}, []byte{})
	assert.NotNil(t, err)
	assert.Equal(t, "test_app", a.app)

	a, err = New("test_app", &MockRedisClient{}, []byte(`[{
        "user": "test",
        "pass": "abc123",
        "auth": [
            "test1",
            "test2"
        ]
    }]`))
	assert.Nil(t, err)
	assert.Equal(t, 1, len(a.authentication))
	assert.Equal(t, "abc123", a.authentication["test"])
	assert.Equal(t, 1, len(a.authorisation))
	assert.Equal(t, 2, len(a.authorisation["test"]))
}

func Test_NewAuth_Authentication(t *testing.T) {
	var a *Auth
	var err error

	a, err = New("test_app", &MockRedisClient{}, []Authentication{})
	assert.Nil(t, err)
	assert.Equal(t, "test_app", a.app)

	a, err = New("test_app", &MockRedisClient{}, []Authentication{
		Authentication{
			User: "test",
			Pass: "abc123",
			Auth: []string{
				"test1",
				"test2",
			},
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(a.authentication))
	assert.Equal(t, "abc123", a.authentication["test"])
	assert.Equal(t, 1, len(a.authorisation))
	assert.Equal(t, 2, len(a.authorisation["test"]))
}

func Test_Token(t *testing.T) {
	auth, _ := New("test_app", &MockRedisClient{}, []byte(`[
        {
            "token": "test1",
            "auth": []
        },
        {
            "token": "test2",
            "auth": [
                "test"
            ]
        },
        {
            "token": "test3",
            "auth": [
                "test",
                "test/*"
            ]
        }
    ]`))

	for k, test := range map[string]struct {
		route, token string
		code         int
	}{
		"no token": {
			"/test", "", http.StatusUnauthorized},
		"token non registered": {
			"/test", "test0", http.StatusUnauthorized},
		"token but no authorisation": {
			"/test", "test1", http.StatusForbidden},
		"token but but not authorised": {
			"/tester", "test2", http.StatusForbidden},
		"all fine": {
			"/test", "test2", http.StatusOK},
		"bad endpoint": {
			"/test/abc", "test2", http.StatusForbidden},
		"all fine, next user": {
			"/test", "test3", http.StatusOK},
		"all fine, next user with extended url": {
			"/test/abc", "test3", http.StatusOK},
		"all fine, next user with extended url - test underscore": {
			"/test/abc_def", "test3", http.StatusOK},
		"all fine, next user with extended url - test dash": {
			"/test/abc-def", "test3", http.StatusOK},
		"all fine, next user with extended url - test tilde": {
			"/test/abc~def", "test3", http.StatusOK},
		"all fine, next user with extended url - test multi underscore": {
			"/test/abc_def_ghi", "test3", http.StatusOK},
		"all fine, next user with extended url - test multi dash": {
			"/test/abc-def-ghi", "test3", http.StatusOK},
		"all fine, next user with extended url - test multi tilde": {
			"/test/abc~def~ghi", "test3", http.StatusOK},
		"all fine, next user with extended url - test multi all": {
			"/test/abc_def-ghi~jkl", "test3", http.StatusOK},
	} {
		t.Run(fmt.Sprintf("#%s", k), func(t *testing.T) {
			var handler = mux.NewRouter()
			handler.Handle(fmt.Sprintf("%s", test.route), auth.Token(func() http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					return
				}
			}())).Methods("GET")

			var server = httptest.NewServer(handler)
			defer server.Close()

			var res = httptest.NewRecorder()
			req, err := http.NewRequest("GET", fmt.Sprintf("%s", test.route), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", test.token))

			handler.ServeHTTP(res, req)

			assert.Equal(t, test.code, res.Code)
		})
	}
}

func Test_Basic(t *testing.T) {
	auth, _ := New("test_app", &MockRedisClient{}, []byte(`[
        {
            "user": "test1",
            "pass": "7987df9d7d6295274858924ab328cc55",
            "auth": []
        },
        {
            "user": "test2",
            "pass": "ec41d671cf2be1b2f2adda930ea3e45b",
            "auth": [
                "test"
            ]
        },
        {
            "user": "test3",
            "pass": "ecfc0c892bd36db48c4c5cc5869bb9c6",
            "auth": [
                "test",
                "test/*"
            ]
        }
    ]`))

	for k, test := range map[string]struct {
		route, username, password string
		code                      int
	}{
		"no user or pass": {
			"/test", "", "", http.StatusUnauthorized},
		"user, but no pass": {
			"/test", "test1", "", http.StatusUnauthorized},
		"user and pass but no authorisation": {
			"/test", "test1", "abc123", http.StatusForbidden},
		"all fine": {
			"/test", "test2", "abc123", http.StatusOK},
		"bad endpoint": {
			"/test/abc", "test2", "abc123", http.StatusForbidden},
		"all fine, next user": {
			"/test", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url": {
			"/test/abc", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test underscore": {
			"/test/abc_def", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test dash": {
			"/test/abc-def", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test tilde": {
			"/test/abc~def", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test multi underscore": {
			"/test/abc_def_ghi", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test multi dash": {
			"/test/abc-def-ghi", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test multi tilde": {
			"/test/abc~def~ghi", "test3", "abc123", http.StatusOK},
		"all fine, next user with extended url - test multi all": {
			"/test/abc_def-ghi~jkl", "test3", "abc123", http.StatusOK},
	} {
		t.Run(fmt.Sprintf("#%s", k), func(t *testing.T) {
			var handler = mux.NewRouter()
			handler.Handle(fmt.Sprintf("%s", test.route), auth.Basic(func() http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					return
				}
			}())).Methods("GET")

			var server = httptest.NewServer(handler)
			defer server.Close()

			var res = httptest.NewRecorder()
			req, err := http.NewRequest("GET", fmt.Sprintf("%s", test.route), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(test.username, test.password)

			handler.ServeHTTP(res, req)

			assert.Equal(t, test.code, res.Code)
		})
	}
}

func Benchmark_BasicAuth(b *testing.B) {
	auth, _ := New("test_app", func() RedisClient {
		r := &MockRedisClient{}
		r.On("Get", mock.Anything, mock.Anything).Return(
			redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
		)
		r.On("Del", mock.Anything, mock.Anything).Return(
			redis.NewIntResult(int64(0), nil),
		)
		r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&redis.StatusCmd{},
		)

		return r
	}(), []byte(`[
		{
			"user": "benchmark_test",
			"pass": "2057bb77b3f8a9d31e1a380596873c87",
			"auth": [
				"test"
			]
		}
	]`))

	var handler = mux.NewRouter()
	handler.Handle("/test", auth.Basic(func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}())).Methods("GET")

	var server = httptest.NewServer(handler)
	defer server.Close()

	for n := 0; n < b.N; n++ {
		var res = httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/test", nil)
		if err != nil {
			b.Fatal(err)
		}
		req.SetBasicAuth("benchmark_test", "abc123")
		handler.ServeHTTP(res, req)
	}
}

func Test_Digest_Auth(t *testing.T) {
	for k, test := range map[string]struct {
		username, qop, payload, response string
		storage                          RedisClient
		code                             int
	}{
		"AUTH - no username present": {
			"", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present, no password for this user": {
			"test fail", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present but upon redis get, an error is returned": {
			"test1", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("", errors.New("Test Error")),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present but the given qop doesnt match expected for this auth": {
			"test1", QOPAuthInt, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present but the given cnonce doesnt match expected for this auth": {
			"test1", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\", \"cnonce\":\"def456hij789\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present but the given nc doesnt match expected for this auth": {
			"test1", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000002\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present and redis entry found for the request but it does not match the provided response, could be tampered with (man in the middle)": {
			"test1", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH - username present and redis entry found for the request and it does match the provided response. The user in this case does not have authorisation": {
			"test1", QOPAuth, "", "cd8108bc1be87a703f40bc7213ba7b24", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusForbidden},

		"AUTH - username present and redis entry found for the request and it does match the provided response. The user in this case does have authorisation": {
			"test2", QOPAuth, "", "e22f199b150e2db4a87df2ac78341add", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusOK},

		"AUTH-INT - no username present": {
			"", QOPAuthInt, "", "",
			func() RedisClient {
				r := &MockRedisClient{}
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)
				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present, no password for this user": {
			"test fail", QOPAuthInt, "", "",
			func() RedisClient {
				r := &MockRedisClient{}
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)
				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present but upon redis get, an error is returned": {
			"test1", QOPAuthInt, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("", errors.New("Test Error")),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present but the given qop doesnt match expected for this auth": {
			"test1", QOPAuth, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("", errors.New("Test Error")),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present but the given cnonce doesnt match expected for this auth": {
			"test1", QOPAuthInt, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\", \"cnonce\":\"def456hij789\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present but the given nc doesnt match expected for this auth": {
			"test1", QOPAuthInt, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000002\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present and redis entry found for the request but it does not match the provided response, could be tampered with (man in the middle)": {
			"test1", QOPAuthInt, "", "", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present and redis entry found for the request and it does match the provided response. The user in this case does not have authorisation": {
			"test1", QOPAuthInt, "Test 1", "d0584855b7c0511107b260e90d494e9d", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusUnauthorized},

		"AUTH-INT - username present and redis entry found for the request and it does match the provided response. The user in this case does have authorisation": {
			"test2", QOPAuthInt, "", "eeab130bfee2768d88cfac2a9afc160e", func() RedisClient {
				r := &MockRedisClient{}
				r.On("Get", mock.Anything, mock.Anything).Return(
					redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
				)
				r.On("Del", mock.Anything, mock.Anything).Return(
					redis.NewIntResult(int64(0), nil),
				)
				r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
					&redis.StatusCmd{},
				)

				return r
			}(), http.StatusOK},
	} {
		t.Run(fmt.Sprintf("#%s", k), func(t *testing.T) {
			auth, _ := New("test_app", test.storage, []byte(`[
		        {
		            "user": "test1",
		            "pass": "7987df9d7d6295274858924ab328cc55",
		            "auth": []
		        },
		        {
		            "user": "test2",
		            "pass": "ec41d671cf2be1b2f2adda930ea3e45b",
		            "auth": [
		                "test"
		            ]
		        }
		    ]`))

			var handler = mux.NewRouter()
			handler.Handle("/test", auth.Digest(test.qop, func() http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					return
				}
			}())).Methods("GET")

			var server = httptest.NewServer(handler)
			defer server.Close()

			var res = httptest.NewRecorder()
			req, err := http.NewRequest("GET", "/test", ioutil.NopCloser(strings.NewReader(test.payload)))
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Authorization", fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
				test.username, "test_app", "ABC-123-DEF-456", "/test?foo=bar", "abc123def456", "00000001", test.qop, test.response))
			handler.ServeHTTP(res, req)

			assert.Equal(t, test.code, res.Code)
		})
	}
}

func Test_md5(t *testing.T) {
	for k, test := range []struct {
		in, exp string
	}{
		{
			"",
			"d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			"test1",
			"5a105e8b9d40e1329780d62ea2265d8a",
		},
		{
			"test2",
			"ad0234829205b9033196ba818f7a872b",
		},
	} {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			assert.Equal(t, test.exp, md5(test.in))
		})
	}
}

func Benchmark_DigestAuth(b *testing.B) {
	auth, _ := New("test_app", func() RedisClient {
		r := &MockRedisClient{}
		r.On("Get", mock.Anything, mock.Anything).Return(
			redis.NewStringResult("{\"nc\":\"00000001\"}", nil),
		)
		r.On("Del", mock.Anything, mock.Anything).Return(
			redis.NewIntResult(int64(0), nil),
		)
		r.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&redis.StatusCmd{},
		)

		return r
	}(), []byte(`[
		{
			"user": "benchmark_test",
			"pass": "2057bb77b3f8a9d31e1a380596873c87",
			"auth": [
				"test"
			]
		}
	]`))

	var handler = mux.NewRouter()
	handler.Handle("/test", auth.Digest("auth", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}())).Methods("GET")

	var server = httptest.NewServer(handler)
	defer server.Close()

	for n := 0; n < b.N; n++ {
		var res = httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/test", nil)
		if err != nil {
			b.Fatal(err)
		}

		req.Header.Set("Authorization", fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
			"benchmark_test", "test_app", "ABC-123-DEF-456", "/test?foo=bar", "abc123def456", "00000001", "auth", "1929bc29bb3ac560435821d030baef6c"))
		handler.ServeHTTP(res, req)
	}
}
