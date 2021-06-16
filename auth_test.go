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

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_MarshalBinary(t *testing.T) {
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)
	assert.Nil(t, enc.Encode(&digestAuth{}))
}

func Test_NewAuth(t *testing.T) {
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

func Test_Basic(t *testing.T) {
	auth, _ := New("test_app", &MockRedisClient{}, []byte(`[
        {
            "user": "test1",
            "pass": "abc123",
            "auth": []
        },
        {
            "user": "test2",
            "pass": "abc123",
            "auth": [
                "test"
            ]
        }
    ]`))

	for k, test := range []struct {
		username, password string
		code               int
	}{
		{"", "", http.StatusUnauthorized},
		{"test1", "", http.StatusUnauthorized},
		{"test1", "abc123", http.StatusForbidden},
		{"test2", "abc123", http.StatusOK},
	} {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			var handler = mux.NewRouter()
			handler.Handle("/test", auth.Basic(func() http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					return
				}
			}())).Methods("GET")

			var server = httptest.NewServer(handler)
			defer server.Close()

			var res = httptest.NewRecorder()
			req, err := http.NewRequest("GET", "/test", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(test.username, test.password)

			handler.ServeHTTP(res, req)

			assert.Equal(t, test.code, res.Code)
		})
	}
}

func Test_Digest_Auth(t *testing.T) {
	for k, test := range []struct {
		username, qop, payload, response string
		storage                          RedisClient
		code                             int
	}{
		// // AUTH
		//
		// // no username present
		{"", QOPAuth, "", "", &MockRedisClient{}, http.StatusUnauthorized},

		// username present but upon redis get, an error is returned
		// returns unathorised and a nonce
		{"test1", QOPAuth, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("", errors.New("Test Error")),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present but the given qop doesnt match expected for this auth
		// returns unathorised and a nonce
		{"test1", QOPAuthInt, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present but the given cnonce doesnt match expected for this auth
		// returns unathorised and a nonce
		{"test1", QOPAuth, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\", \"cnonce\":\"def456hij789\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present but the given nc doesnt match expected for this auth
		// returns unathorised and a nonce
		{"test1", QOPAuth, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000002\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present and redis entry found for the request but it does not
		// match the provided response, could be tampered with (man in the middle)
		// returns unathorised and a nonce
		{"test1", QOPAuth, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present and redis entry found for the request and it does match
		// the provided response. The user in this case does not have authorisation
		// returns forbidden response
		{"test1", QOPAuth, "", "015e3688f2e9a5f26bc6d5245c2de408", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusForbidden},

		// username present and redis entry found for the request and it does match
		// the provided respose. The user in this case does have authorisation
		// returns OK response
		{"test2", QOPAuth, "", "015e3688f2e9a5f26bc6d5245c2de408", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusOK},

		// AUTH-INT

		// no username present
		{"", QOPAuthInt, "", "", &MockRedisClient{}, http.StatusUnauthorized},

		// username present but upon redis get, an error is returned
		// returns unathorised and a nonce
		{"test1", QOPAuthInt, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("", errors.New("Test Error")),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present but the given qop doesnt match expected for this auth
		// returns unathorised and a nonce
		{"test1", QOPAuth, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("", errors.New("Test Error")),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present but the given cnonce doesnt match expected for this auth
		// returns unathorised and a nonce
		{"test1", QOPAuthInt, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\", \"cnonce\":\"def456hij789\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present but the given nc doesnt match expected for this auth
		// returns unathorised and a nonce
		{"test1", QOPAuthInt, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000002\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present and redis entry found for the request but it does not
		// match the provided response, could be tampered with (man in the middle)
		// returns unathorised and a nonce
		{"test1", QOPAuthInt, "", "", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present and redis entry found for the request and it does match
		// the provided response because the body doesnt match. The user in this
		// case does not have authorisation
		// returns forbidden response
		{"test1", QOPAuthInt, "Test 1", "d0584855b7c0511107b260e90d494e9d", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusUnauthorized},

		// username present and redis entry found for the request and it does match
		// the provided response. The user in this case does not have authorisation
		// returns forbidden response
		{"test1", QOPAuthInt, "Test", "d0584855b7c0511107b260e90d494e9d", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusForbidden},

		// username present and redis entry found for the request and it does match
		// the provided respose. The user in this case does have authorisation
		// returns OK response
		{"test2", QOPAuthInt, "", "2e8c1dd087d73f82e6f5de280a00932d", func() RedisClient {
			r := &MockRedisClient{}
			r.On("Get", mock.Anything).Return(
				redis.NewStringResult("{\"ha1\":\"abc\", \"nc\":\"00000001\"}", nil),
			)
			r.On("Del", mock.Anything).Return(
				redis.NewIntResult(int64(0), nil),
			)
			r.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(
				&redis.StatusCmd{},
			)

			return r
		}(), http.StatusOK},
	} {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			auth, _ := New("test_app", test.storage, []byte(`[
		        {
		            "user": "test1",
		            "pass": "abc123",
		            "auth": []
		        },
		        {
		            "user": "test2",
		            "pass": "abc123",
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
