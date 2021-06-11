# Auth Handler Wrapper

`go get github.com/shane-exley/auth`

This is used to apply authentication to a handler by wrapping the handler in the desired authentication method.

- Basic

Simple username and password authentication.

- Digest

Nonce based on RFC 4122 and DCE 1.1: Authentication and Security Services. See [Wiki](https://en.wikipedia.org/wiki/Digest_access_authentication) for further details on operation and usage. In this package we use a redis cache instance to store and manage the nonce handling.

## Usage

```
import "github.com/shane-exley/auth"
```

The idea is that you take in an http.Handler and return a new one that does something else before and/or after calling the ServeHTTP method on the original.

Now, wherever I pass my original http.Handler I can wrap it such that

```
http.Handler("/path", handleSomething)
```

becomes

```
http.Handler("/path", a.Basic(handleSomething))
```

But first we need to instantiate `a` providing our realm to use, our redis cache storage instance (for digest) and the [configuration](#Configuration).

```
// For Basic
a, err := auth.New("http://test.com", nil, []byte(`[{ "user":"test","pass":"abc123", "auth": ["test1","test2"]}]`))
http.Handler("/path", a.Basic(handleSomething))


// For Digest
a, err := auth.New("http://test.com", redis.NewClient(), []byte(`[{ "user":"test","pass":"abc123", "auth": ["test1","test2"]}]`))
http.Handler("/path", a.Digest(auth.QOPAuth, handleSomething))
```

## Configuration

The configuration for the auth package is a simple JSON setup following the below format it needs to be an array of users, each with a username, password and auth:

```
[{
    "user": "test",
    "pass": "abc123",
    "auth": [
        "path1",
        "path2"
    ]
}]
```

The auth relates to the path/endpoint we are allowing access for that particular user.
