GOPATH := $(shell pwd)

encryptor: encrypt.go decrypt.go main.go
	GOPATH=$(GOPATH) go build -o $@

test: encryptor
	cat Makefile | ./encryptor -publickey test/public.pem encrypt | ./encryptor -privatekey test/private.pem decrypt | diff Makefile -
