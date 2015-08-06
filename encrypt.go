package main

import (
  "os"
  "io"
  "io/ioutil"
  "archive/tar"
  "crypto/rand"
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
}

func (writer *EncryptionWriter) writeToTar(name string, toWrite []byte) {
  err := writer.wr.WriteHeader(&tar.Header{Name: name, Size: int64(len(toWrite))})
  if (err != nil) {
    writer.err = err
    log.Println(err)
  }

  _, err = writer.wr.Write(toWrite)
  if (err != nil) {
    writer.err = err
    log.Println(err)
  }
}

func (writer *EncryptionWriter) Write(data []byte) (int, error) {
  if (writer.err != nil) {
    return 0, writer.err
  }

  toWrite, err := writer.ctx.EncryptUpdate(data)
  if (err != nil) {
    writer.err = err
    log.Println(err)
  }

  writer.writeToTar("value", toWrite)

  return len(data), err
}

func (writer *EncryptionWriter) Finish() {
  toWrite, err := writer.ctx.EncryptFinal()
  if (err != nil) {
    writer.err = err
    log.Println(err)
  }
  writer.writeToTar("close", toWrite)
  writer.wr.Flush()
}

func addEncryptedKeyToTar(tarFile *tar.Writer, key []byte) {
  tarFile.WriteHeader(&tar.Header{
    Name: "key",
    Size: int64(len(key)),
  })
  tarFile.Write(key)
}

func addEncryptedDataToTar(tarFile *tar.Writer, cipher *openssl.Cipher, key []byte, input io.ReadCloser) {
  ctx, err := openssl.NewEncryptionCipherCtx(cipher, nil, key, randomBytes(cipher.IVSize()))
  if (err != nil) {
    log.Fatalln(err)
  }

  writer := &EncryptionWriter {wr: tarFile, ctx:  ctx,}

  io.Copy(writer, input)
  writer.Finish()
}

func Encrypt(publicKey *openssl.PublicKey, input io.ReadCloser, output io.WriteCloser) {
  cipher, err := openssl.GetCipherByName("aes-256-cbc")
  if (err != nil) {
    log.Fatalln(err)
  }

  key := randomBytes(cipher.KeySize())

  tarFile := tar.NewWriter(output)

  addEncryptedKeyToTar(tarFile, key)
  addEncryptedDataToTar(tarFile, cipher, key, input)

  tarFile.Close()
}

func ReadPublicKey(filename string) (*openssl.PublicKey){
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

func main() {
  Encrypt(ReadPublicKey(os.Args[1]), os.Stdin, os.Stdout)
}
