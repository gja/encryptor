package main

import (
  "io"
  "io/ioutil"
  "archive/tar"
  "crypto/rand"
  "fmt"
  "log"
  "github.com/spacemonkeygo/openssl"
  "os/exec"
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

// Replace this. Need to patch go's openssl to expose RSA_public_encrypt
func encryptKey(key []byte, publicKeyFile *string) ([]byte) {
  cmd := exec.Command("openssl", "rsautl", "-encrypt", "-inkey", *publicKeyFile, "-pubin")
  outPipe, err := cmd.StdinPipe()
  if (err != nil) {
    log.Fatalln(err)
  }
  inPipe, err := cmd.StdoutPipe()
  if (err != nil) {
    log.Fatalln(err)
  }
  outPipe.Write(key)
  outPipe.Close()

  go cmd.Run()

  encryptedKey, err := ioutil.ReadAll(inPipe)
  if (err != nil) {
    log.Fatalln(err)
  }

  return encryptedKey
}

func newEncryptionWriter(publicKey *string, output io.Writer) (*EncryptionWriter) {
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
  writer.writeToTar("key", encryptKey(key, publicKey))
  writer.writeToTar("iv", iv)

  return writer
}

func Encrypt(publicKey *string, input io.ReadCloser, output io.WriteCloser) {
  encryptionWriter := newEncryptionWriter(publicKey, output)
  io.Copy(encryptionWriter, input)
  encryptionWriter.finish()
}
