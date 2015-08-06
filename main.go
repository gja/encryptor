package main
import (
  "flag"
  "os"
)

func main() {
  _ = flag.String("publickey", "public.pem", "Path to public.pem")
  _ = flag.String("privatekey", "private.pem", "Path to private.pem")
  flag.Parse()
  action := flag.Arg(0)

  if (action == "decrypt") {
    Decrypt(nil, os.Stdin, os.Stdout)
  } else {
    Encrypt(nil, os.Stdin, os.Stdout)
  }
}