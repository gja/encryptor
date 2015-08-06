GOPATH := $(shell pwd)

encryptor: encrypt.go decrypt.go
	GOPATH=$(GOPATH) go build
