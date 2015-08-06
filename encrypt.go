package main

import (
  "os"
  "io"
  "io/ioutil"
  "archive/tar"
  "crypto/rand"
  "fmt"
  "log"
  "github.com/spacemonkeygo/openssl"
)

func randomBytes(num int) (key []byte) {
  key = make([]byte, num, num)
  n, err := rand.Read(key)
  if (err != nil || n != num) {
    log.Fatalln(err)
  }
  return key
}

type EncryptionWriter struct {
  err error
  wr *tar.Writer
  ctx openssl.EncryptionCipherCtx
  count int
}

func (writer *EncryptionWriter) writeToTar(name string, toWrite []byte) {
  err := writer.wr.WriteHeader(&tar.Header{Name: name, Size: int64(len(toWrite))})
  if (err != nil) {
    log.Fatalln(err)
  }

  _, err = writer.wr.Write(toWrite)
  if (err != nil) {
    log.Fatalln(err)
  }
}

func (writer *EncryptionWriter) Write(data []byte) (int, error) {
  if (writer.err != nil) {
    return 0, writer.err
  }

  toWrite, err := writer.ctx.EncryptUpdate(data)
  if (err != nil) {
    writer.err = err
    log.Fatalln(err)
  }

  writer.writeToTar(fmt.Sprintf("value%d", writer.count), toWrite)
  writer.count += 1

  return len(data), err
}

func (writer *EncryptionWriter) finish() {
  toWrite, err := writer.ctx.EncryptFinal()
  if (err != nil) {
    writer.err = err
    log.Fatalln(err)
  }
  writer.writeToTar("close", toWrite)
  writer.wr.Flush()
  writer.wr.Close()
}

func newEncryptionWriter(publicKey *openssl.PublicKey, output io.Writer) (*EncryptionWriter) {
  cipher, err := openssl.GetCipherByName("aes-256-cbc")
  if (err != nil) {
    log.Fatalln(err)
  }

  key := randomBytes(cipher.KeySize())
  iv := randomBytes(cipher.IVSize())
  ctx, err := openssl.NewEncryptionCipherCtx(cipher, nil, key, iv)
  if (err != nil) {
    log.Fatalln(err)
  }

  tarFile := tar.NewWriter(output)
  writer := &EncryptionWriter {wr: tarFile, ctx:  ctx,}
  writer.writeToTar("key", key)
  writer.writeToTar("iv", iv)

  return writer
}

func Encrypt(publicKey *openssl.PublicKey, input io.ReadCloser, output io.WriteCloser) {
  encryptionWriter := newEncryptionWriter(publicKey, output)
  io.Copy(encryptionWriter, input)
  encryptionWriter.finish()
}

func readPublicKey(filename string) (*openssl.PublicKey){
  keyBytes, err := ioutil.ReadFile(filename)
  if (err != nil) {
    log.Fatalln(err)
  }
  publicKey, err := openssl.LoadPublicKeyFromPEM(keyBytes)
  if (err != nil) {
    log.Fatalln(err)
  }
  return &publicKey
}

func maien() {
  Encrypt(readPublicKey(os.Args[1]), os.Stdin, os.Stdout)
}
