package main

import (
  "io"
  "io/ioutil"
  "archive/tar"
  "log"
  "github.com/spacemonkeygo/openssl"
)

func min(a, b int64) int64 {
   if a < b {
      return a
   }
   return b
}

type EncryptionReader struct {
  rd *tar.Reader
  ctx openssl.DecryptionCipherCtx
  remainingInFile int64
}

func (reader *EncryptionReader) readNextBytes(b []byte) (int, error) {
  bytesToRead := make([]byte, min(int64(len(b)), reader.remainingInFile))
  n, readerr := reader.rd.Read(bytesToRead)

  if (n == 0) {
    return n, readerr
  }

  reader.remainingInFile = reader.remainingInFile - int64(n)

  buf, err := reader.ctx.DecryptUpdate(bytesToRead)
  if (err != nil) {
    log.Fatalln(err)
  }
  copy(b, buf)
  return len(buf), readerr
}

func (reader *EncryptionReader) Read(b []byte) (int, error) {
  if (reader.remainingInFile == 0) {
    header, err := reader.rd.Next()
    if(err == io.EOF) {
      return 0, err
    }
    if(err != nil) {
      log.Fatalln(err)
    }
    reader.remainingInFile = header.Size
  }

  return reader.readNextBytes(b)
}

func readNextEntry(tarFile *tar.Reader) ([]byte) {
  _, err := tarFile.Next()
  if (err != nil) {
    log.Fatalln(err)
  }
  result, err := ioutil.ReadAll(tarFile)
  if (err != nil) {
    log.Fatalln(err)
  }
  return result
}

func (writer *EncryptionReader) finish() ([]byte) {
  toWrite, err := writer.ctx.DecryptFinal()
  if (err != nil) {
    log.Fatalln(err)
  }

  return toWrite
}

func newEncryptionReader(privateKey *openssl.PrivateKey, input io.Reader) (*EncryptionReader) {
  tarFile := tar.NewReader(input)

  key := readNextEntry(tarFile)
  iv := readNextEntry(tarFile)

  cipher, err := openssl.GetCipherByName("aes-256-cbc")
  if (err != nil) {
    log.Fatalln(err)
  }

  ctx, err := openssl.NewDecryptionCipherCtx(cipher, nil, key, iv)
  if (err != nil) {
    log.Fatalln(err)
  }

  return &EncryptionReader { rd: tarFile, ctx: ctx, }
}


func Decrypt(privateKey *openssl.PrivateKey, input io.ReadCloser, output io.WriteCloser) {
  reader := newEncryptionReader(privateKey, input)
  io.Copy(output, reader)
  output.Write(reader.finish())
}
