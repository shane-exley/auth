# Auth Handler Wrapper

`go get github.com/shane-exley/auth/v2`

This is used to apply authentication to a handler by wrapping the handler in the desired authentication method.

- Basic

Simple username and password authentication.

- Digest

Nonce based on RFC 4122 and DCE 1.1: Authentication and Security Services. See [Wiki](https://en.wikipedia.org/wiki/Digest_access_authentication) for further details on operation and usage. In this package we use a redis cache instance to store and manage the nonce handling.

- HMAC

Using a SHA256 keyed hashing to conform to RFC 4104 this is the more secure of the available authentication, see [wiki](https://en.wikipedia.org/wiki/HMAC) for further details on operation and usage .

## Usage

```go
import "github.com/shane-exley/auth/v2"
```

The idea is that you take in an http.Handler and return a new one that does something else before and/or after calling the ServeHTTP method on the original.

Now, wherever I pass my original http.Handler I can wrap it such that

```go
http.Handler("/path", handleSomething)
```

becomes

```go
http.Handler("/path", a.Basic(handleSomething))
```

But first we need to instantiate `a` providing our realm to use, our redis cache storage instance (for digest) and the [configuration](#Configuration).

```go
// For Token
a, err := auth.New("http://test.com", nil,
    []auth.Role{
        auth.Role{
            ID: "role1",
            Auth: []string{
                "path",
                "path2",
                "path2/*",
            },
        }
    },
    []auth.Authentication{
        auth.Authentication{
            Token: "testtoken",
            Roles: []string{
                "role1",
            },
            Rate: auth.AuthenticationRate{
                Burst: 1,
                Limit: 2,
            },
        },
    }
)

// or / the same as

a, err := auth.New("http://test.com", nil,
    []byte(`{
        "role1": [
            "path1",
            "path2",
            "path2/*"
        ]
    }`),
    []byte(`[{
        "token": "testtoken",
        "roles": [
            "role1"
        ],
        "rate": {
            "burst": 1,
            "limit": 2
        }
    }]`)
)

http.Handler("/path", a.Token(handleSomething))
http.Handler("/path2", a.Token(handleSomething))
http.Handler("/path2/abc", a.Token(handleSomething))

// For Basic
a, err := auth.New("http://test.com", nil,
    []auth.Role{
        auth.Role{
            ID: "role1",
            Auth: []string{
                "path",
                "path2",
                "path2/*",
            },
        }
    },
    []auth.Authentication{
        auth.Authentication{
            User: "test",
             // note for basic auth that the pass attribute in the authentication must conform to the format MD5(<user>:<app>:<client password>)
            Pass: "abc123",
            Roles: []string{
                "role1"
            },
            Rate: auth.AuthenticationRate{
                Burst: 1,
                Limit: 2,
            },
        },
    }
)

// or / the same as

a, err := auth.New("http://test.com", nil,
    []byte(`{
        "role1": [
            "path1",
            "path2",
            "path2/*"
        ]
    }`),
    // note for basic auth that the pass attribute in the authentication must conform to the format MD5(<user>:<app>:<client password>)
    []byte(`[{
        "user": "test",
        "pass": "abc123",
        "roles": [
            "role1"
        ],
        "rate": {
            "burst": 1,
            "limit": 2
        }
    }]`)
)

http.Handler("/path", a.Basic(handleSomething))
http.Handler("/path2", a.Basic(handleSomething))
http.Handler("/path2/abc", a.Basic(handleSomething))

// For Digest
a, err := auth.New("http://test.com", redis.NewClient(),
    []auth.Role{
        auth.Role{
            ID: "role1",
            Auth: []string{
                "path",
                "path2",
                "path2/*",
            },
        }
    },
    []auth.Authentication{
        auth.Authentication{
            User: "test",
            Pass: "abc123",
            Roles: []string{
                "role1",
            },
            Rate: auth.AuthenticationRate{
                Burst: 1,
                Limit: 2,
            },
        },
    }
)

// or / the same as

a, err := auth.New("http://test.com", redis.NewClient(),
    []byte(`{
        "role1": [
            "path1",
            "path2",
            "path2/*"
        ]
    }`),
    []byte(`[{
        "user": "test",
        "pass": "abc123",
        "roles": [
            "role1"
        ],
        "rate": {
            "burst": 1,
            "limit": 2
        }
    }]`)
)

http.Handler("/path", a.Digest(auth.QOPAuth, handleSomething))
http.Handler("/path2", a.Digest(auth.QOPAuth, handleSomething))
http.Handler("/path2/abc", a.Digest(auth.QOPAuth, handleSomething))

// For HMAC
a, err := auth.New("http://test.com", redis.NewClient(),
    []auth.Role{
        auth.Role{
            ID: "role1",
            Auth: []string{
                "path",
                "path2",
                "path2/*",
            },
        }
    },
    []auth.Authentication{
        auth.Authentication{
            User: "test",
            // Note for HMAC that differs from Basic Auth is that the password matches that of whats given to the client
            Pass: "abc123",
            Roles: []string{
                "role1",
            },
            Rate: auth.AuthenticationRate{
                Burst: 1,
                Limit: 2,
            },
        },
    }
)

// or / the same as

a, err := auth.New("http://test.com", redis.NewClient(),
    []byte(`{
        "role1": [
            "path1",
            "path2",
            "path2/*"
        ]
    }`),
    // Note for HMAC that differs from Basic Auth is that the password matches that of whats given to the client
    []byte(`[{
        "user": "test",
        "pass": "abc123",
        "roles": [
            "role1"
        ],
        "rate": {
            "burst": 1,
            "limit": 2
        }
    }]`)
)

http.Handler("/path", a.HMAC(handleSomething))
http.Handler("/path2", a.HMAC(handleSomething))
http.Handler("/path2/abc", a.HMAC(handleSomething))
```

## Configuration

The configuration for the auth package is two simple JSON setups following the below format:

  - Firstly we need to define the roles and the access for which each role allows

```json
{
    "role1": [
        "path1/*",
        "path2/*"
    ],
    "role2": [
        "path3/*"
    ],
    "role3": [
        "path4/*"
    ],
}
```

  - The second config is an array of users, each with a username, password and the roles to which assign to

```json
[{
    "user": "test1",
    "pass": "abc123",
    "roles": [
        "role1",
        "role2"
    ],
    "rate": {
        "burst": 1,
        "limit": 2
    }
},{
    "user": "test2",
    "pass": "efg123",
    "roles": [
        "role2",
        "role3"
    ],
    "rate": {
        "burst": 1,
        "limit": 2
    }
}]
```

The auth relates to the path/endpoint we are allowing access for that particular user.

## Testing

```bash
// unit
go test ./...
```

```bash
// benchmark
go test -bench=.
```
