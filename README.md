# The [Bitcoin Message Tool](https://github.com/shadowy-pycoder/bitcoin_message_tool) in Go

A lightweight CLI tool for signing and verification of bitcoin messages. Bitcoin message is the most straightforward and natural way to prove ownership over a given address without revealing any confidential information.

This tool closely follows specification described in [BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)

## Installation

```shell
go install github.com/shadowy-pycoder/go-bitcoin-message-tool/cmd/bmt@latest
```
This will install the `bmt` binary to your `$GOPATH/bin` directory.

## Usage

### General
```shell
bmt -h

██████╗ ███╗   ███╗████████╗
██╔══██╗████╗ ████║╚══██╔══╝
██████╔╝██╔████╔██║   ██║   
██╔══██╗██║╚██╔╝██║   ██║   
██████╔╝██║ ╚═╝ ██║   ██║   
╚═════╝ ╚═╝     ╚═╝   ╚═╝ 

Bitcoin Message Tool by shadowy-pycoder 

GitHub: https://github.com/shadowy-pycoder

Usage: bmt [OPTIONS] COMMAND
Options:

  -h    show this help message and exit

Commands:

  sign         Create bitcoin message 
  verify       Verify bitcoin message 
  create       Create wallet (private key, public key, addresses)
``` 

### Message signing
```shell
Usage bmt sign [-h] -p -a {legacy, nested, segwit} -m [MESSAGE ...] [-d] [-e]
Options:

  -a value
        type of bitcoin address (legacy, nested, segwit)
  -d    sign deterministically (RFC6979)
  -e    create electrum-like signature
  -h    show this help message and exit
  -m string
        [MESSAGE ...] message to sign
  -p    private key in wallet import format (WIF)

Examples:

Deterministic signature for compressed private key and legacy address

bmt sign -p -a legacy -d -m "ECDSA is the most fun I have ever experienced"
PrivateKey (WIF): L3V9AFB763LKWWsMh8CyosSG8QV8KDTjYeXqkt4WX5Xyz2aNqLAY
-----BEGIN BITCOIN SIGNED MESSAGE-----
ECDSA is the most fun I have ever experienced
-----BEGIN BITCOIN SIGNATURE-----
16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t

H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI=
-----END BITCOIN SIGNATURE-----
```

### Message verification
```shell
Usage bmt verify [-h] [-f | -a ADDRESS -m [MESSAGE ...] -s SIGNATURE] [-e] [-v] [-r]
Options:

  -a string
        ADDRESS bitcoin address
  -e    verify electrum-like signature
  -f    verify message in RFC2440-like format
  -h    show this help message and exit
  -m string
        [MESSAGE ...] message to verify
  -r    recover public key
  -s value
        SIGNATURE bitcoin signature in base64 format
  -v    show full message

Examples:

Message verification in verbose mode

bmt verify -a 175A5YsPUdM71mnNCC3i8faxxYJgBonjWL \
-m "ECDSA is the most fun I have ever experienced" \
-s HyiLDcQQ1p2bKmyqM0e5oIBQtKSZds4kJQ+VbZWpr0kYA6Qkam2MlUeTr+lm1teUGHuLapfa43JjyrRqdSA0pxs= \
-v
true
message verified to be from 175A5YsPUdM71mnNCC3i8faxxYJgBonjWL

Display a recovered public key

bmt verify -a 175A5YsPUdM71mnNCC3i8faxxYJgBonjWL \
-m "ECDSA is the most fun I have ever experienced" \
-s HyiLDcQQ1p2bKmyqM0e5oIBQtKSZds4kJQ+VbZWpr0kYA6Qkam2MlUeTr+lm1teUGHuLapfa43JjyrRqdSA0pxs= \
-r
true
024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1

Verify message in RFC2440-like format

bmt verify -f -v -r   
Insert message in RFC2440-like format (or Ctrl+C to quit):
-----BEGIN BITCOIN SIGNED MESSAGE-----
ECDSA is the most fun I have ever experienced
-----BEGIN BITCOIN SIGNATURE-----
16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t

H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI=
-----END BITCOIN SIGNATURE-----
true
message verified to be from 16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t
02700317e20cefbcd8a9e2f294ff2585bc0b8dc981bfe68f72c42497d1b5239988
```

### Wallet creation
```shell
Usage bmt create [-h] [-n {1...1000000}] [-path]
Options:

  -h    show this help message and exit
  -n value
        number of wallets to create [1...1000000] (default 1)
  -path string
        path to a file to write created wallets (if ommited prints to stdout)

Examples:

Create 100 key pairs with addresses and write to wallets.txt

bmt create -n 100 -path=./wallets.txt

Create a wallet and print to console (you can redirect output to a file)

bmt create -n 1
Private Key (HEX): 850cece14ffefdb864f6007718a5243dae9194841617c7d6d77b67482d40d856
Private Key (WIF): L1gLtHEKG4FbbxQDzth3ksCZ4jTSjRvcU7K2KDeDE368pG8MjkFg
Public Key (Raw): (X=691ab7d2b2e1b41a8df334a5471a3abd7a93c8822b2abf3de64c552147dc33b8, Y=b1eed621c6b9e790a901ca30eb55ee95d591c3e6dc2e6aa30f2b9f5c525e7e32)
Public Key (HEX Compressed): 02691ab7d2b2e1b41a8df334a5471a3abd7a93c8822b2abf3de64c552147dc33b8
Legacy Address: 1N3kZRUrEioGxXQbSyCWuBwmoFp4T62i93
Nested SegWit Address: 3KWsrxLMHPU1v8riptj33zCsWD8bf6jfLF
Native SegWit Address: bc1qum0at29ayuq2ndk39z4zwf4zdpxv5ker570ape
Taproot Address: bc1p5utaw0g77graev5yw575c3jnzh8j88ezzw39lgr250ghppwpyccsvjkvyp
```