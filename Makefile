GOPATH := $(shell pwd)

encryptor: encrypt.go decrypt.go main.go
	GOPATH=$(GOPATH) go build
