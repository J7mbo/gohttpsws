# gohttpsws

#### A simple go tls webserver example that works for both dev and prod.

[![Build Status](https://travis-ci.com/J7mbo/gohttpsws.svg?token=yHmxZpU2vJZUs1GXsdCa&branch=master)](https://travis-ci.com/J7mbo/gohttpsws)
[![GoDoc](https://godoc.org/github.com/J7mbo/gohttpsws?status.svg)](https://godoc.org/github.com/J7mbo/gohttpsws)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

> I regularly find myself re-using the same simple code to set up a webserver in Go with TLS for both dev and prod.
> So I placed it in a library for simpler re-use.

### Pre-requisites

- [mkcert](https://github.com/FiloSottile/mkcert) on your host machine (macos: `brew install mkcert`)

### Usage - Dev

1. Generate ca, cert and key using mkcert:

```bash
CAROOT=./certs mkcert -install
CAROOT=./certs mkcert -cert-file ./certs/cert.pem -key-file ./certs/key.pem localhost 127.0.0.1
```

*On MacOS these are added to your Keychain, so you can manage them using Keychain Access > System > Certificates.*

This will give you `ca.pem`, `cert.pem` and `key.pem` in the directory you run the command from.

2. Use these when invoking the library. Make sure to _absolute paths_ for the files:

```go
package main

import (
	"github.com/gorilla/mux"
	"github.com/j7mbo/gohttpsws"
)

func main() {
	c := gohttpsws.NewConfig(
		"8080",
		"/absolute/path/to/cert.pem",
		"/absolute/path/to/key.pem",
		"/absolute/path/to/rootCA.pem",
	)
	s, _ := gohttpsws.NewServer(c)

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World"))
	})

	if err := s.ServeDev(r); err != nil {
		panic(err)
	}
}
```

### Usage - Prod

Use `ServeProd()` instead of dev, and provide the certificate and key.

Ideally use letsencrypt and point to the files generated by the letsencrypt binary. The certificate authority is not
needed.