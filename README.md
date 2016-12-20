# MISP Golang

So far, only search is implemented but it might already be enough for several use
cases.

# Installation

```
go get github.com/golang-misp
```

# Testing

Before testing, you need to put a valid `config.json` file under the testing
directory `misp/test`. Copy the `config.json.example` found at the root of the
project and modify it.

```
# Go to misp/test directory
go test -v
```

# Documentation

Install the golang-misp package into your go project.

```
go doc misp
```
