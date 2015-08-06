GOPATH := $(shell pwd)

encryptor: encrypt.go
	GOPATH=$(GOPATH) go build
