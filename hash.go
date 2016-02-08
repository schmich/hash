package main

import (
  "os"
  "io"
  "io/ioutil"
  "fmt"
  "hash"
  "encoding/hex"
  "golang.org/x/crypto/md4"
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  "golang.org/x/crypto/sha3"
  "golang.org/x/crypto/ripemd160"
  "github.com/htruong/go-md2"
  "github.com/jawher/mow.cli"
)

func computeHash(algo hash.Hash, input io.Reader) []byte {
  io.Copy(algo, input)
  return algo.Sum(nil)
}

func basicHash(factory func() hash.Hash) func(io.Reader) []byte {
  return func(input io.Reader) []byte {
    return computeHash(factory(), input)
  }
}

func printHash(fileName string, hashFunc func(io.Reader) []byte) {
  var input io.Reader

  if len(fileName) == 0 {
    input = os.Stdin
  } else {
    file, err := os.Open(fileName)
    if err != nil {
      fmt.Println(err)
      return
    }

    defer file.Close()
    input = file
  }

  hash := hashFunc(input)
  fmt.Println(hex.EncodeToString(hash))
}

func addHashCommand(app *cli.Cli, command string, description string, hashFunc func(io.Reader) []byte) {
  app.Command(command, description, func(cmd *cli.Cmd) {
    cmd.Spec = "[FILE]"

    file := cmd.StringArg("FILE", "", "File to hash.")

    cmd.Action = func() {
      printHash(*file, hashFunc)
    }
  })
}

func addShakeCommand(app *cli.Cli, command string, description string, shakeSum func([]byte, []byte), defaultOutputBytes int) {
  app.Command(command, description, func(cmd *cli.Cmd) {
    cmd.Spec = "[-n] [FILE]"

    file := cmd.StringArg("FILE", "", "File to hash.")
    bytes := cmd.IntOpt("n", defaultOutputBytes, "Output length (bytes).")

    hashFunc := func(input io.Reader) []byte {
      data, err := ioutil.ReadAll(input)
      if err != nil {
        panic(err)
      }

      hash := make([]byte, *bytes)
      shakeSum(hash, data)
      return hash
    }

    cmd.Action = func() {
      printHash(*file, hashFunc)
    }
  })
}

func run(args []string) {
  app := cli.App("hash", "Hash stuff - https://github.com/schmich/hash")
  addHashCommand(app, "md2", "MD2 hash, 128-bit (MD2)", basicHash(md2.New))
  addHashCommand(app, "md4", "MD4 hash, 128-bit (MD4)", basicHash(md4.New))
  addHashCommand(app, "md5", "MD5 hash, 128-bit (MD5)", basicHash(md5.New))
  addHashCommand(app, "sha1", "SHA-1 hash, 160-bit (SHA-1)", basicHash(sha1.New))
  addHashCommand(app, "sha2-224", "SHA-2 hash, 224-bit (SHA-224)", basicHash(sha256.New224))
  addHashCommand(app, "sha2-256", "SHA-2 hash, 256-bit (SHA-256)", basicHash(sha256.New))
  addHashCommand(app, "sha2-384", "SHA-2 hash, 384-bit (SHA-384)", basicHash(sha512.New384))
  addHashCommand(app, "sha2-512", "SHA-2 hash, 512-bit (SHA-512)", basicHash(sha512.New))
  addHashCommand(app, "sha2-512/224", "SHA-2 hash, 224-bit (SHA-512/224)", basicHash(sha512.New512_224))
  addHashCommand(app, "sha2-512/256", "SHA-2 hash, 256-bit (SHA-512/256)", basicHash(sha512.New512_256))
  addHashCommand(app, "sha3-224", "SHA-3 hash, 224-bit (SHA3-224)", basicHash(sha3.New224))
  addHashCommand(app, "sha3-256", "SHA-3 hash, 256-bit (SHA3-256)", basicHash(sha3.New256))
  addHashCommand(app, "sha3-384", "SHA-3 hash, 384-bit (SHA3-384)", basicHash(sha3.New384))
  addHashCommand(app, "sha3-512", "SHA-3 hash, 512-bit (SHA3-512)", basicHash(sha3.New512))
  addHashCommand(app, "sha3-512", "SHA-3 hash, 512-bit (SHA3-512)", basicHash(sha3.New512))
  addShakeCommand(app, "shake-128", "SHA-3 hash, n-byte (SHAKE-128)", sha3.ShakeSum128, 32)
  addShakeCommand(app, "shake-256", "SHA-3 hash, n-byte (SHAKE-256)", sha3.ShakeSum256, 64)
  addHashCommand(app, "ripemd-160", "RIPEMD hash, 160-bit (RIPEMD-160)", basicHash(ripemd160.New))
  app.Run(args)
}

func main() {
  run(os.Args)
}
