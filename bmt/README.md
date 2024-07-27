# The Bitcoin Message Tool

## Installation

```shell
go get github.com/shadowy-pycoder/go-bitcoin-message-tool@latest
```

## Usage
```go
package main

import (
	"fmt"

	"github.com/shadowy-pycoder/go-bitcoin-message-tool/bmt"
)

func main() {
    wifStr := bmt.NewStr("Kx4XofogMJhEdvHGSMRdztgEg3BBHs9B18yv9uBe1VphNcpKyMnF")
    w, _ := bmt.CreateNewWallet(nil, wifStr)
    fmt.Println(w)
    fmt.Println()
    fmt.Println(w.PrivateKey().Hex())
    fmt.Println(w.PrivateKey().Wif())
    fmt.Println(w.PublicKey())
    fmt.Println(w.PublicKeyRaw())
    fmt.Println(w.LegacyAddress())
    fmt.Println(w.SegwitAddress())
    fmt.Println(w.NestedSegwitAddress())
    fmt.Println(w.TaprootAddress())

    var p bmt.JacobianPoint
    p.Mul(w.PrivateKey().Hex(), bmt.GenPoint)
    fmt.Println(p.ToAffine().Eq(w.PublicKeyRaw()))
}
```
```shell
Private Key (HEX): 191d8aa8b3e52eaa12b9754bf56d118d754602a3b74701678b3d63a93a3b27a2
Private Key (WIF): Kx4XofogMJhEdvHGSMRdztgEg3BBHs9B18yv9uBe1VphNcpKyMnF
Public Key (Raw): (X=d4f0b6554af7e3108dda04c44bc5cd727b13ba9c8bc614ca61462fbca98b4807, Y=361359e859074eb33df657b6b37a6a80b1694657fcc84580b505bdd1497665ec)
Public Key (HEX Compressed): 02d4f0b6554af7e3108dda04c44bc5cd727b13ba9c8bc614ca61462fbca98b4807
Legacy Address: 1AvumVcXFP5hEJBAMkCeFegzhWAM1gvGeZ
Nested SegWit Address: 38CeDX7CWZ5PAUfMw3pgmF98R8X3U9ePpf
Native SegWit Address: bc1qdn4nnn59570wlkdn4tq23whw6y5e6c28p7chr5
Taproot Address: bc1pvm2y9rm950593kglq758620aew3n2gcfhdcrnt868l2nr3u4yetsduhsra


191d8aa8b3e52eaa12b9754bf56d118d754602a3b74701678b3d63a93a3b27a2
Kx4XofogMJhEdvHGSMRdztgEg3BBHs9B18yv9uBe1VphNcpKyMnF
02d4f0b6554af7e3108dda04c44bc5cd727b13ba9c8bc614ca61462fbca98b4807
(X=d4f0b6554af7e3108dda04c44bc5cd727b13ba9c8bc614ca61462fbca98b4807, Y=361359e859074eb33df657b6b37a6a80b1694657fcc84580b505bdd1497665ec)
1AvumVcXFP5hEJBAMkCeFegzhWAM1gvGeZ
bc1qdn4nnn59570wlkdn4tq23whw6y5e6c28p7chr5
38CeDX7CWZ5PAUfMw3pgmF98R8X3U9ePpf
bc1pvm2y9rm950593kglq758620aew3n2gcfhdcrnt868l2nr3u4yetsduhsra
true
```

## Benchmarks
```shell
make bench10k
go test -o ./bmt ./bmt -bench=. -benchmem -run=^$ -benchtime 10000x -cpuprofile='./bmt/cpu.prof' -memprofile='./bmt/mem.prof'
goos: linux
goarch: amd64
pkg: github.com/shadowy-pycoder/go-bitcoin-message-tool/bmt
cpu: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
BenchmarkCreateWallets-8                           10000             79132 ns/op            5028 B/op         70 allocs/op
BenchmarkCreateNewWalletFromHex-8                  10000            277714 ns/op            2249 B/op         49 allocs/op
BenchmarkCreateNewWalletFromWif-8                  10000            278893 ns/op            2196 B/op         47 allocs/op
BenchmarkDblPoint-8                                10000               383.8 ns/op             0 B/op          0 allocs/op
BenchmarkAddPoints-8                               10000              1149 ns/op               0 B/op          0 allocs/op
BenchmarkMulGenPoint-8                             10000            130584 ns/op               1 B/op          0 allocs/op
BenchmarkMulPoint-8                                10000            229323 ns/op               3 B/op          0 allocs/op
BenchmarkSignMessageDeterministic-8                10000           1078618 ns/op            7553 B/op        131 allocs/op
BenchmarkSignMessageNonDeterministic-8             10000            895601 ns/op            3951 B/op         81 allocs/op
BenchmarkVerifyMessage-8                           10000            417738 ns/op            2013 B/op         34 allocs/op
BenchmarkConvertToBits-8                           10000               342.4 ns/op             0 B/op          0 allocs/op
BenchmarkValidateKey-8                             10000                36.67 ns/op            0 B/op          0 allocs/op
BenchmarkParseRFCMessage-8                         10000               690.1 ns/op           160 B/op          2 allocs/op
PASS
ok      github.com/shadowy-pycoder/go-bitcoin-message-tool/bmt  34.127s

```