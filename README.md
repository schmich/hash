# Hash

Hash stuff.

## Installation

    go get -u github.com/schmich/hash/... && go install github.com/schmich/hash/...

## Usage

    > hash --help
    
    Usage: hash COMMAND [arg...]
    
    Hash stuff - https://github.com/schmich/hash
    
    Commands:
      md2            MD2 hash, 128-bit (MD2)
      md4            MD4 hash, 128-bit (MD4)
      md5            MD5 hash, 128-bit (MD5)
      sha1           SHA-1 hash, 160-bit (SHA-1)
      sha2-224       SHA-2 hash, 224-bit (SHA-224)
      sha2-256       SHA-2 hash, 256-bit (SHA-256)
      sha2-384       SHA-2 hash, 384-bit (SHA-384)
      sha2-512       SHA-2 hash, 512-bit (SHA-512)
      sha2-512/224   SHA-2 hash, 224-bit (SHA-512/224)
      sha2-512/256   SHA-2 hash, 256-bit (SHA-512/256)
      sha3-224       SHA-3 hash, 224-bit (SHA3-224)
      sha3-256       SHA-3 hash, 256-bit (SHA3-256)
      sha3-384       SHA-3 hash, 384-bit (SHA3-384)
      sha3-512       SHA-3 hash, 512-bit (SHA3-512)
      sha3-512       SHA-3 hash, 512-bit (SHA3-512)
      shake-128      SHA-3 hash, n-byte (SHAKE-128)
      shake-256      SHA-3 hash, n-byte (SHAKE-256)
      ripemd-160     RIPEMD hash, 160-bit (RIPEMD-160)

## Examples

`hash` operates on files or stdin. The SHAKE hash family is parameterized to produce arbitrary-length output, though going beyond a certain length does not provide any additional cryptographic security.

    > hash md5 empty.txt
    d41d8cd98f00b204e9800998ecf8427e

    > echo foo | hash ripemd-160
    a54aa4d578e906894f0e420ea35d51c68f8516fd

    > hash sha2-256 < test.txt
    59d06cb1c4c102c96153e2b1f8834408285b4818dc495b15131a374d78eb8ed5

    > hash shake-128 empty.txt
    7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26

    > hash shake-128 -n 40 empty.txt
    7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93

# License

Copyright &copy; 2016 Chris Schmich<br>
MIT License. See [LICENSE](LICENSE) for details.
