# vulnz - Use golang.org/x/vuln to scan your dependencies

`vulnz` uses [golang.org/x/vuln](https://pkg.go.dev/golang.org/x/vuln) to scan the dependencies in your `go.mod`.

## Install

`go install github.com/tebeka/vulnz`


## Use

```
$ vulnz 

golang.org/x/crypto: GO-2020-0012: An attacker can craft an ssh-ed25519 or sk-ssh-ed25519@openssh.com public
key, such that the library will panic when trying to verify a signature
with it. If verifying signatures using user supplied public keys, this
may be used as a denial of service vector.
https://go-review.googlesource.com/c/crypto/+/220357
https://github.com/golang/crypto/commit/bac4c82f69751a6dd76e702d54b3ceb88adab236
https://groups.google.com/g/golang-announce/c/3L45YRc91SY

...
```

Yeah, too many false positives - I *might* work on it :)
