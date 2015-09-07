GOPATH := $(shell pwd)/vendor

deps:
	GOPATH=$(GOPATH) go get -d

encryptor: deps encrypt.go decrypt.go main.go
	GOPATH=$(GOPATH) go build -o $@

end2endtest: encryptor
	cat test/test-data | ./encryptor -publickey test/public.pem encrypt | ./encryptor -privatekey test/private.pem decrypt | diff test/test-data -

v1formatcompatibletest: encryptor
	cat test/encrypted-test-data | ./encryptor -privatekey test/private.pem decrypt | diff test/test-data -

tests: end2endtest v1formatcompatibletest
