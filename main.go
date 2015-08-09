package main
import (
  "flag"
  "os"
  "github.com/gja/openssl"
  "io/ioutil"
  "log"
)

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

func readPrivateKey(filename string) (*openssl.PrivateKey){
  keyBytes, err := ioutil.ReadFile(filename)
  if (err != nil) {
    log.Fatalln(err)
  }
  publicKey, err := openssl.LoadPrivateKeyFromPEM(keyBytes)
  if (err != nil) {
    log.Fatalln(err)
  }
  return &publicKey
}


func main() {
  publicKey := flag.String("publickey", "public.pem", "Path to public.pem")
  privateKey := flag.String("privatekey", "private.pem", "Path to private.pem")
  flag.Parse()
  action := flag.Arg(0)

  if (action == "decrypt") {
    Decrypt(readPrivateKey(*privateKey), os.Stdin, os.Stdout)
  } else {
    Encrypt(readPublicKey(*publicKey), os.Stdin, os.Stdout)
  }
}
