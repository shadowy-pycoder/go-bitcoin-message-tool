package bmt

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/golangcrypto/ripemd160"
	"github.com/mr-tron/base58"
	"golang.org/x/term"
)

var (
	zero         = big.NewInt(0)
	one          = big.NewInt(1)
	two          = big.NewInt(2)
	three        = big.NewInt(3)
	four         = big.NewInt(4)
	eight        = big.NewInt(8)
	pCurve, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	nCurve, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	aCurve       = zero
	bCurve       = big.NewInt(7)
	genPointX, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	genPointY, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	pow256       big.Int
	pow256M1     = pow256.Exp(two, big.NewInt(256), nil).Sub(&pow256, one)
	precomputes  = getPrecomputes()
	secp256k1    = Secp256k1{
		PCurve:   pCurve,
		NCurve:   nCurve,
		ACurve:   aCurve,
		BCurve:   bCurve,
		GenPoint: NewJacobianPoint(genPointX, genPointY, one),
	}
	identityPoint = NewJacobianPoint(pCurve, zero, one)
	addressTypes  = []string{"legacy", "nested", "segwit"}
	headers       = [5][4]byte{
		{0x1b, 0x1c, 0x1d, 0x1e}, // 27 - 30 P2PKH uncompressed
		{0x1f, 0x20, 0x21, 0x22}, // 31 - 34 P2PKH compressed
		{0x23, 0x24, 0x25, 0x26}, // 35 - 38 P2WPKH-P2SH compressed (BIP-137)
		{0x27, 0x28, 0x29, 0x2a}, // 39 - 42 P2WPKH compressed (BIP-137)
		{0x2b, 0x2c, 0x2d, 0x2e}, // TODO 43 - 46 P2TR
	}
	OutOfRangeError = &PrivateKeyError{Message: "scalar is out of range"}
	flags           = flag.NewFlagSet("bitcoin message tool", flag.ExitOnError)
	usagePrefix     = `
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
`
	usageCommands = `
Commands:

  sign         Create bitcoin message 
  verify       Verify bitcoin message 
`
	signUsagePrefix = `Usage bmt sign [-h] -p -a {legacy, nested, segwit} -m [MESSAGE ...] [-d] [-e]
Options:
`
	signUsageExamples = `
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
`
	verifyUsagePrefix = `Usage bmt verify [-h] [-f | -a ADDRESS -m [MESSAGE ...] -s SIGNATURE] [-e] [-v] [-r]
Options:
`
	verifyUsageExamples = `
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
`
	createUsagePrefix = `Usage bmt create [-h] [-n {1...1000000}] [-path]
Options:
`
	createUsageExamples = `
Examples:

Create 100 key pairs with addresses and write to wallets.txt

bmt create -n 100 -path=./wallets.txt

Create a wallet and print to console (you can redirect output to a file)

bmt create -n 1
Private Key (Raw): 60180445912902181241548287604652662614241904941006823251259342289760572987478
Private Key (WIF): L1gLtHEKG4FbbxQDzth3ksCZ4jTSjRvcU7K2KDeDE368pG8MjkFg
Public Key (Raw): (x=47540055824935908510461373219072689454917771939693273636263256867956974171064, y=80481361684980169856026167260820025559478707302150175078848962789012628471346)
Public Key (HEX Copmpressed): 02691ab7d2b2e1b41a8df334a5471a3abd7a93c8822b2abf3de64c552147dc33b8
Legacy Address: 1N3kZRUrEioGxXQbSyCWuBwmoFp4T62i93
Nested SegWit Address: 3KWsrxLMHPU1v8riptj33zCsWD8bf6jfLF
Native SegWit Address: bc1qum0at29ayuq2ndk39z4zwf4zdpxv5ker570ape
`
	beginSignedMessage = "-----BEGIN BITCOIN SIGNED MESSAGE-----"
	beginSignature     = "-----BEGIN BITCOIN SIGNATURE-----"
	endSignature       = "-----END BITCOIN SIGNATURE-----"
)

type PrivateKeyError struct {
	Message string
	Err     error
}

func (e *PrivateKeyError) Error() string { return e.Message }
func (e *PrivateKeyError) Unwrap() error { return e.Err }

type PointError struct {
	Message string
	Err     error
}

func (e *PointError) Error() string { return e.Message }
func (e *PointError) Unwrap() error { return e.Err }

type SignatureError struct {
	Message string
	Err     error
}

func (e *SignatureError) Error() string { return e.Message }
func (e *SignatureError) Unwrap() error { return e.Err }

type JacobianPoint struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
}

// NewJacobianPoint creates a new JacobianPoint with the given coordinates.
//
// Parameters:
//   - x: a pointer to a big.Int representing the x-coordinate.
//   - y: a pointer to a big.Int representing the y-coordinate.
//   - z: a pointer to a big.Int representing the z-coordinate.
//
// Returns:
//   - a pointer to a JacobianPoint struct representing the new point.
func NewJacobianPoint(x, y, z *big.Int) *JacobianPoint {
	return &JacobianPoint{
		X: new(big.Int).Set(x),
		Y: new(big.Int).Set(y),
		Z: new(big.Int).Set(z)}
}

// Eq compares the current JacobianPoint with another JacobianPoint.
//
// Parameters:
//   - q: the JacobianPoint to compare with.
//
// Returns:
//   - bool: true if the points are equal, false otherwise.
func (pt *JacobianPoint) Eq(q *JacobianPoint) bool {
	return pt.X.Cmp(q.X) == 0 && pt.Y.Cmp(q.Y) == 0 && pt.Z.Cmp(q.Z) == 0
}

// Dbl performs a point doubling operation in the elliptic curve cryptography with 256 Bit Primes.
//
// Parameter:
//   - p: a pointer to a JacobianPoint struct representing the point to be doubled.
//
// Returns:
// A pointer to a JacobianPoint struct representing the result of the point doubling operation.
//
// Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes
// Shay Gueron, Vlad Krasnov
// https://eprint.iacr.org/2013/816.pdf page 4
func (pt *JacobianPoint) Dbl(p *JacobianPoint) *JacobianPoint {
	var Y2, S, M, x, y, z, tx, ty big.Int
	if p.X.Cmp(secp256k1.PCurve) == 0 {
		pt.X = new(big.Int).Set(p.X)
		pt.Y = new(big.Int).Set(p.Y)
		pt.Z = new(big.Int).Set(p.Z)
		return pt
	}
	Y2.Mul(p.Y, p.Y)
	S.Mul(four, p.X).Mul(&S, &Y2).Mod(&S, secp256k1.PCurve)
	M.Mul(three, p.X).Mul(&M, p.X)
	x.Mul(&M, &M).Sub(&x, tx.Mul(two, &S)).Mod(&x, secp256k1.PCurve)
	y.Mul(&M, ty.Sub(&S, &x)).Sub(&y, ty.Mul(&Y2, &Y2).Mul(&ty, eight)).Mod(&y, secp256k1.PCurve)
	z.Mul(two, p.Y).Mul(&z, p.Z).Mod(&z, secp256k1.PCurve)
	pt.X = &x
	pt.Y = &y
	pt.Z = &z
	return pt
}

// Add performs elliptic curve point addition in Jacobian coordinates for the secp256k1 curve.
//
// It takes two JacobianPoint points p and q as input parameters and returns a JacobianPoint point.
//
// Parameters:
//   - p: a pointer to a JacobianPoint representing the first point.
//   - q: a pointer to a JacobianPoint representing the second point.
//
// Returns:
//   - a pointer to a JacobianPoint representing the sum of p and q.
//
// Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes
// Shay Gueron, Vlad Krasnov
// https://eprint.iacr.org/2013/816.pdf page 4
func (pt *JacobianPoint) Add(p, q *JacobianPoint) *JacobianPoint {
	var PZ2, QZ2, U1, U2, S1, S2, H, R, H2, H3, x, tx, y, ty, z big.Int
	if p.X.Cmp(secp256k1.PCurve) == 0 {
		pt.X = new(big.Int).Set(q.X)
		pt.Y = new(big.Int).Set(q.Y)
		pt.Z = new(big.Int).Set(q.Z)
		return pt
	}
	if q.X.Cmp(secp256k1.PCurve) == 0 {
		pt.X = new(big.Int).Set(p.X)
		pt.Y = new(big.Int).Set(p.Y)
		pt.Z = new(big.Int).Set(p.Z)
		return pt
	}
	PZ2.Mul(p.Z, p.Z)
	QZ2.Mul(q.Z, q.Z)
	U1.Mul(p.X, &QZ2).Mod(&U1, secp256k1.PCurve)
	U2.Mul(q.X, &PZ2).Mod(&U2, secp256k1.PCurve)
	S1.Mul(p.Y, &QZ2).Mul(&S1, q.Z).Mod(&S1, secp256k1.PCurve)
	S2.Mul(q.Y, &PZ2).Mul(&S2, p.Z).Mod(&S2, secp256k1.PCurve)

	if U1.Cmp(&U2) == 0 {
		if S1.Cmp(&S2) == 0 {
			return pt.Dbl(p)
		} else {
			pt.X = new(big.Int).Set(identityPoint.X)
			pt.Y = new(big.Int).Set(identityPoint.Y)
			pt.Z = new(big.Int).Set(identityPoint.Z)
			return pt
		}

	}
	H.Sub(&U2, &U1).Mod(&H, secp256k1.PCurve)
	R.Sub(&S2, &S1).Mod(&R, secp256k1.PCurve)
	H2.Mul(&H, &H).Mod(&H2, secp256k1.PCurve)
	H3.Mul(&H2, &H).Mod(&H3, secp256k1.PCurve)
	x.Mul(&R, &R).Sub(&x, &H3).Sub(&x, tx.Mul(two, &U1).Mul(&tx, &H2)).Mod(&x, secp256k1.PCurve)
	y.Mul(&R, y.Mul(&U1, &H2).Sub(&y, &x)).Sub(&y, ty.Mul(&S1, &H3)).Mod(&y, secp256k1.PCurve)
	z.Mul(&H, p.Z).Mul(&z, q.Z).Mod(&z, secp256k1.PCurve)
	pt.X = &x
	pt.Y = &y
	pt.Z = &z
	return pt
}

func getPrecomputes() []*JacobianPoint {
	precomputes := make([]*JacobianPoint, 256)
	p := NewJacobianPoint(secp256k1.GenPoint.X, secp256k1.GenPoint.Y, secp256k1.GenPoint.Z)
	for i := range len(precomputes) {
		precomputes[i] = NewJacobianPoint(p.X, p.Y, p.Z)
		p.Dbl(p)
	}
	return precomputes
}

// Mul performs elliptic curve multiplication.
//
// It takes two parameters:
//   - scalar: a pointer to a big.Int representing the scalar value.
//   - p: a pointer to a JacobianPoint representing the point to be multiplied.
//
// It returns a pointer to a JacobianPoint representing the result of the multiplication.
//
// https://paulmillr.com/posts/noble-secp256k1-fast-ecc/#fighting-timing-attacks
func (pt *JacobianPoint) Mul(scalar *big.Int, p *JacobianPoint) *JacobianPoint {
	var n, fakeN big.Int
	n.Set(scalar)
	pnt := NewJacobianPoint(identityPoint.X, identityPoint.Y, identityPoint.Z)
	if p == nil {
		fakeP := NewJacobianPoint(identityPoint.X, identityPoint.Y, identityPoint.Z)
		fakeN.Xor(pow256M1, &n)
		for _, q := range precomputes {
			if IsOdd(&n) {
				pnt.Add(pnt, q)
			} else {
				fakeP.Add(fakeP, q)
			}
			n.Rsh(&n, 1)
			fakeN.Rsh(&fakeN, 1)

		}
	} else {
		q := NewJacobianPoint(p.X, p.Y, p.Z)
		for n.Cmp(zero) == 1 {
			if IsOdd(&n) {
				pnt.Add(pnt, q)
			}
			n.Rsh(&n, 1)
			q.Dbl(q)
		}
	}
	pt.X = pnt.X
	pt.Y = pnt.Y
	pt.Z = pnt.Z
	return pt
}

// ToAffine converts a point from Jacobian coordinates to affine coordinates.
//
// Parameter:
//   - p: the point in Jacobian coordinates.
//
// Returns:
// A pointer to a Point representing the point in affine coordinates.
func (pt *JacobianPoint) ToAffine() *Point {
	var x, y big.Int
	invZ := ModInverse(pt.Z, secp256k1.PCurve)
	invZ2 := new(big.Int).Exp(invZ, two, nil)
	x.Mul(pt.X, invZ2).Mod(&x, secp256k1.PCurve)
	y.Mul(pt.Y, invZ2).Mul(&y, invZ).Mod(&y, secp256k1.PCurve)
	return &Point{X: &x, Y: &y}
}

// String returns a string representation of the JacobianPoint struct.
//
// It returns a string in the format "(x=<X>, y=<Y>, z=<Z>)", where <X>, <Y> and <Z> are the
// string representations of the X, Y and Z coordinates of the JacobianPoint.
func (pt *JacobianPoint) String() string {
	return fmt.Sprintf("(x=%s, y=%s, z=%s)", pt.X, pt.Y, pt.Z)
}

type Point struct {
	X *big.Int
	Y *big.Int
}

// String returns a string representation of the Point struct.
//
// It returns a string in the format "(x=<X>, y=<Y>)", where <X> and <Y> are the
// string representations of the X and Y coordinates of the Point.
func (pt *Point) String() string {
	return fmt.Sprintf("(x=%s, y=%s)", pt.X, pt.Y)
}

// ToJacobian converts a point from affine coordinates to Jacobian coordinates.
//
// Parameter:
//   - p: a pointer to a Point representing the point in affine coordinates.
//
// Returns:
// A pointer to a JacobianPoint representing the point in Jacobian coordinates.
func (pt *Point) ToJacobian() *JacobianPoint {
	return NewJacobianPoint(pt.X, pt.Y, one)
}

// Valid checks if a given point is on the elliptic curve.
//
// Parameters:
//   - p: a pointer to a Point representing the point to be validated.
//
// Returns:
//   - bool: true if the point is valid, false otherwise.
func (pt *Point) Valid() bool {
	var r1, r2 big.Int
	r1.Exp(pt.X, three, nil).Add(&r1, secp256k1.BCurve).Mod(&r1, secp256k1.PCurve)
	r2.Exp(pt.Y, two, secp256k1.PCurve)
	return r1.Cmp(&r2) == 0
}

type Secp256k1 struct {
	PCurve   *big.Int
	NCurve   *big.Int
	ACurve   *big.Int
	BCurve   *big.Int
	GenPoint *JacobianPoint
}

type Signature struct {
	R *big.Int
	S *big.Int
}

type BitcoinMessage struct {
	Address   string
	Data      string
	Signature []byte
}

type PrivateKey struct {
	Raw          *big.Int
	Wif          *string
	Uncompressed bool
}

// generate generates a random big.Int value within the range of secp256k1.NCurve.
//
// It sets the value of the receiver PrivateKey's raw field to the generated random big.Int.
func generate() (*big.Int, error) {
	if n, err := rand.Int(rand.Reader, secp256k1.NCurve); err != nil {
		return nil, &PrivateKeyError{Message: "failed generating random ineteger", Err: err}
	} else {
		return n, nil
	}
}

// NewPrivateKey generates a new PrivateKey object.
//
// It takes in two parameters:
//   - raw: a pointer to a big.Int object representing the raw value of the private key.
//   - wif: a pointer to a string representing the WIF (Wallet Import Format) of the private key.
//
// The function returns a pointer to a PrivateKey object and an error.
//
//   - If both raw and wif are provided, it returns an error.
//   - If neither raw nor wif is provided, it generates a random private key and returns a new PrivateKey object.
//   - If only wif is provided, it creates a new PrivateKey object with the provided WIF.
//   - If only raw is provided, it creates a new PrivateKey object with the provided raw value.
//
// The function checks if the generated or provided private key is valid.
// If the private key is invalid, it returns an error.
//
// The function also encodes the generated or provided private key using the Wif() method.
// If the encoding fails, it returns an error.
//
// The function returns a pointer to the newly created PrivateKey object.
func NewPrivateKey(raw *big.Int, wif *string) (*PrivateKey, error) {
	var (
		pk  PrivateKey
		err error
	)
	if raw != nil && wif != nil {
		return nil, &PrivateKeyError{Message: "cannot specify both raw and wif"}
	}
	if raw == nil && wif == nil {
		pk.Raw, err = generate()
		if err != nil {
			return nil, err
		}
		if !ValidKey(pk.Raw) {
			return nil, OutOfRangeError
		}
		pk.Uncompressed = false
		encoded, err := pk.ToWif(pk.Uncompressed)
		if err != nil {
			return nil, err
		}
		pk.Wif = encoded
	} else if wif == nil {
		pk.Raw = new(big.Int).Set(raw)
		if !ValidKey(pk.Raw) {
			return nil, OutOfRangeError
		}
		pk.Uncompressed = false
		encoded, err := pk.ToWif(pk.Uncompressed)
		if err != nil {
			return nil, err
		}
		pk.Wif = encoded
	} else if raw == nil {
		pk.Wif = wif
		uncompressed, err := pk.ToInt()
		if err != nil {
			return nil, err
		}
		pk.Uncompressed = uncompressed
	}
	return &pk, nil
}

// SplitBytes splits the private key bytes into three parts: the version byte, the private key bytes, and the checksum bytes.
//
// It takes no parameters.
// It returns three byte slices: the version byte, the private key bytes, and the checksum bytes.
func (k *PrivateKey) SplitBytes() (version []byte, payload []byte, checkSum []byte, err error) {
	privkey, err := base58.Decode(*k.Wif)
	if err != nil {
		return nil, nil, nil, err
	}
	pkLen := len(privkey)
	if pkLen-4 < 1 {
		return nil, nil, nil, &PrivateKeyError{Message: "too short"}
	}
	return privkey[:1], privkey[1 : pkLen-4], privkey[pkLen-4:], nil
}

// Int calculates the integer value of the private key.
//
// It returns a boolean indicating if the key is uncompressed and an error if any.
func (k *PrivateKey) ToInt() (uncompressed bool, err error) {
	var (
		privKeyInt big.Int
	)
	if k.Wif == nil {
		return false, &PrivateKeyError{Message: "wif cannot be empty"}
	}
	version, priVkey, checkSum, err := k.SplitBytes()
	if err != nil {
		return false, &PrivateKeyError{Message: "failed decoding wif string", Err: err}
	}
	if !validCheckSum(version, priVkey, checkSum) {
		return false, &PrivateKeyError{Message: "invalid wif checksum"}
	}
	if len(priVkey) == 33 {
		privKeyInt.SetBytes(priVkey[:len(priVkey)-1])
		uncompressed = false
	} else {
		privKeyInt.SetBytes(priVkey)
		uncompressed = true
	}
	if !ValidKey(&privKeyInt) {
		return false, OutOfRangeError
	}
	k.Raw = &privKeyInt
	return uncompressed, nil
}

// Wif generates the Wallet Import Format (WIF) for the private key.
//
// It takes a boolean uncompressed indicating if the key is uncompressed.
// It returns a pointer to a string and an error.
func (k *PrivateKey) ToWif(uncompressed bool) (*string, error) {
	if !ValidKey(k.Raw) {
		return nil, OutOfRangeError
	}
	buf := make([]byte, 32)
	pk := joinBytes([][]byte{{0x80}, k.Raw.FillBytes(buf), {0x01}}...)
	if uncompressed {
		pk = pk[:len(pk)-1]
	}
	converted := base58.Encode(joinBytes([][]byte{pk, checkSum(pk)}...))
	k.Wif = &converted
	return k.Wif, nil
}

// CreateNewWallet generates a new wallet with private key, public key, and various address types.
//
// Returns:
//   - A pointer to a Wallet struct representing the new wallet.
func CreateNewWallet() *Wallet {
	privKey, _ := NewPrivateKey(nil, nil)
	rawPubKey, _ := createRawPubKey(privKey.Raw)
	pubKey := createPubKey(rawPubKey, false)
	legacyAddress := createAddress(pubKey)
	nestedAddress := createNestedSegwit(pubKey)
	nativeAddress := createNativeSegwit(pubKey)
	return &Wallet{PrivKey: privKey,
		RawPubKey: rawPubKey,
		PubKey:    hex.EncodeToString(pubKey),
		Legacy:    legacyAddress,
		Nested:    nestedAddress,
		Native:    nativeAddress}

}

type Wallet struct {
	PrivKey   *PrivateKey
	RawPubKey *Point
	PubKey    string
	Legacy    string
	Nested    string
	Native    string
}

// String returns a formatted string representation of the Wallet.
//
// It concatenates the private key (raw), private key (WIF), public key (raw),
// public key (hex compressed), legacy address, nested segwit address, and
// native segwit address into a single string.
//
// Returns:
//   - A string containing the formatted representation of the Wallet.
func (w *Wallet) String() string {
	return fmt.Sprintf(`Private Key (Raw): %s
Private Key (WIF): %s
Public Key (Raw): %s
Public Key (HEX Copmpressed): %s
Legacy Address: %s
Nested SegWit Address: %s
Native SegWit Address: %s
`, w.PrivKey.Raw, *w.PrivKey.Wif, w.RawPubKey, w.PubKey, w.Legacy, w.Nested, w.Native)
}

// ValidKey checks if the given big.Int scalar is a valid key.
//
// Parameters:
//   - scalar: a pointer to a big.Int representing the scalar value.
//
// Returns:
//   - bool: true if the scalar is valid, false otherwise.
func ValidKey(scalar *big.Int) bool {
	if scalar == nil {
		return false
	}
	return scalar.Cmp(zero) == 1 && scalar.Cmp(secp256k1.NCurve) == -1
}

// IsOdd checks if the given big.Int is odd.
//
// It takes a pointer to a big.Int as a parameter.
// It returns a boolean indicating whether the number is odd or not.
func IsOdd(n *big.Int) bool {
	return n.Bit(0) == 1
}

// ModInverse calculates the modular inverse of a number.
//
// It takes two parameters: n and mod, both of type *big.Int.
// The function returns a pointer to a new *big.Int representing the modular inverse of n modulo mod.
func ModInverse(n, mod *big.Int) *big.Int {
	return new(big.Int).ModInverse(n, mod)
}

// DoubleSHA256 calculates the SHA256 hash of the input byte slice twice.
//
// Parameter:
//   - b: input byte slice to be hashed.
//
// Returns:
// The double SHA256 hashed byte slice.
func DoubleSHA256(b []byte) []byte {
	h1 := sha256.New()
	h2 := sha256.New()
	if _, err := h1.Write(b); err != nil {
		panic(err)
	}
	if _, err := h2.Write(h1.Sum(nil)); err != nil {
		panic(err)
	}
	return h2.Sum(nil)

}

// Ripemd160SHA256 computes the RIPEMD160 hash of the SHA-256 hash of the input byte slice.
//
// Parameter:
//   - b: input byte slice to be hashed.
//
// Returns:
// The RIPEMD160 hashed byte slice.
func Ripemd160SHA256(b []byte) []byte {
	h := sha256.New()
	r := ripemd160.New()
	if _, err := h.Write(b); err != nil {
		panic(err)
	}
	if _, err := r.Write(h.Sum(nil)); err != nil {
		panic(err)
	}
	return r.Sum(nil)
}

// joinBytes concatenates the byte slices in s into a single byte slice.
//
//   - s: variadic parameter containing byte slices to be concatenated.
//
// Returns a byte slice.
func joinBytes(s ...[]byte) []byte {
	n := 0
	for _, v := range s {
		n += len(v)
	}

	b, i := make([]byte, n), 0
	for _, v := range s {
		i += copy(b[i:], v)
	}
	return b
}

// createRawPubKey generates a raw public key from a given private key.
//
// Parameters:
//   - privKey: a pointer to a big.Int representing the private key.
//
// Returns:
//   - a pointer to a Point representing the raw public key.
//   - an error if the generated point is not on the curve.
func createRawPubKey(privKey *big.Int) (*Point, error) {
	var p JacobianPoint
	rawPubKey := p.Mul(privKey, nil).ToAffine()
	if !rawPubKey.Valid() {
		return nil, &PointError{Message: "point is not on curve"}
	}
	return rawPubKey, nil
}

// createPubKey generates a public key in compressed or uncompressed format
// from a given raw public key.
//
// Parameters:
//   - rawPubKey: a pointer to a Point representing the raw public key.
//   - uncompressed: a boolean indicating whether to return the public key in
//     uncompressed format.
//
// Returns:
//   - a byte slice representing the public key in the specified format.
func createPubKey(rawPubKey *Point, uncompressed bool) []byte {
	var prefix uint8
	buf := make([]byte, 65)
	if uncompressed {
		buf[0] = 0x04
		rawPubKey.X.FillBytes(buf[1:33])
		rawPubKey.Y.FillBytes(buf[33:])
		return buf
	}
	if IsOdd(rawPubKey.Y) {
		prefix = 0x03
	} else {
		prefix = 0x02
	}
	buf[0] = prefix
	rawPubKey.X.FillBytes(buf[1:33])
	return buf[:33]
}

// checkSum calculates the checksum of the input byte slice using DoubleSHA256 and returns the first 4 bytes.
//
// Parameters:
//   - v: the input byte slice to calculate the checksum.
//
// Returns:
//   - A byte slice representing the calculated checksum.
func checkSum(v []byte) []byte {
	return DoubleSHA256(v)[:4]
}

func validCheckSum(ver, privKey, checkSum []byte) bool {
	return bytes.Equal(DoubleSHA256(joinBytes([][]byte{ver, privKey}...))[:4], checkSum)
}

// createAddress generates a Bitcoin address from a given public key.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//
// Returns:
//   - a string representing the Bitcoin address.
func createAddress(pubKey []byte) string {
	address := joinBytes([][]byte{{0x00}, Ripemd160SHA256(pubKey)}...)
	return base58.Encode(joinBytes([][]byte{address, checkSum(address)}...))
}

// createNestedSegwit generates a nested SegWit Bitcoin address from a given public key.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//
// Returns:
//   - a string representing the nested SegWit Bitcoin address.
func createNestedSegwit(pubKey []byte) string {
	address := joinBytes([][]byte{{0x05}, Ripemd160SHA256(joinBytes([][]byte{{0x00, 0x14}, Ripemd160SHA256(pubKey)}...))}...)
	return base58.Encode(joinBytes([][]byte{address, checkSum(address)}...))
}

// createNativeSegwit generates a native SegWit Bitcoin address from a given public key.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//
// Returns:
//   - a string representing the native SegWit Bitcoin address.
func createNativeSegwit(pubKey []byte) string {
	converted, err := bech32.ConvertBits(Ripemd160SHA256(pubKey), 8, 5, true)
	if err != nil {
		panic(err)
	}
	combined := make([]byte, len(converted)+1)
	combined[0] = byte(0)
	copy(combined[1:], converted)
	addr, err := bech32.Encode("bc", combined)
	if err != nil {
		panic(err)
	}
	return addr
}

// varInt generates a variable-length integer in bytes based on the input length.
//
// Parameters:
//   - length: an unsigned 64-bit integer representing the length to be encoded.
//
// Returns:
//   - a byte slice representing the variable-length integer in bytes.
//
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
func varInt(length uint64) []byte {
	var (
		lenBytes int
		prefix   byte
	)
	if length < 0xFD {
		return []byte{uint8(length)}
	}
	if length <= 0xFFFF {
		lenBytes = 2
		prefix = 0xFD
	} else if length <= 0xFFFFFFFF {
		lenBytes = 4
		prefix = 0xFE
	} else if length <= 0xFFFFFFFFFFFFFFFF {
		lenBytes = 8
		prefix = 0xFF
	}
	bs := make([]byte, 9)
	bs[0] = prefix
	binary.LittleEndian.PutUint64(bs[1:], length)
	return bs[:lenBytes+1]
}

// msgMagic generates a Bitcoin message magic byte sequence from the given message.
//
// Parameters:
//   - msg: a string representing the message.
//
// Returns:
//   - A byte slice representing the Bitcoin message magic byte sequence.
//
// https://bitcoin.stackexchange.com/questions/77324/how-are-bitcoin-signed-messages-generated
func msgMagic(msg string) []byte {
	message := []byte(msg)
	return joinBytes([][]byte{{0x18}, []byte("Bitcoin Signed Message:\n"), varInt(uint64(len(message))), message}...)
}

// signed calculates the signature of a message using the provided private key.
//
// Parameters:
//   - privKey: a pointer to a big.Int representing the private key.
//   - msg: a pointer to a hash of a signature (usually double sha256 of a message with 'msgMagic' applied).
//   - k: nonce that comes from random (SystemRandom) or pseudorandom source (RFC6979).
//
// Returns:
//   - *Signature: a pointer to a Signature struct containing the calculated signature components.
func signed(msg, privKey, k *big.Int) *Signature {
	var (
		r, s big.Int
		p    JacobianPoint
	)
	if !ValidKey(k) {
		return nil
	}
	point := p.Mul(k, nil).ToAffine()
	r.Set(point.X).Mod(&r, secp256k1.NCurve)
	if r.Cmp(zero) == 0 || point.ToJacobian().Eq(identityPoint) {
		return nil
	}
	s.Mul(ModInverse(k, secp256k1.NCurve), s.Add(msg, s.Mul(privKey, &r))).Mod(&s, secp256k1.NCurve)
	if s.Cmp(zero) == 0 {
		return nil
	}
	if s.Cmp(new(big.Int).Rsh(secp256k1.NCurve, 1)) == 1 {
		s.Sub(secp256k1.NCurve, &s)
	}
	return &Signature{R: &r, S: &s}
}

// sign generates a signature based on the provided private key and message.
//
// Parameters:
//   - privKey: a pointer to a big.Int representing the private key.
//   - msg: a pointer to a big.Int representing the message.
//
// Returns:
//   - *Signature: a pointer to a Signature struct containing the generated signature.
//
// https://learnmeabitcoin.com/technical/ecdsa#sign
func sign(privKey, msg *big.Int) *Signature {
	var (
		k   *big.Int
		err error
		sig *Signature
	)
	for {
		k, err = generate()
		if err != nil {
			panic(err)
		}
		sig = signed(msg, privKey, k)
		if sig != nil {
			return sig
		}
	}
}

// bitsToInt converts a byte slice to a big.Int and adjusts its length to match qLen.
//
// Parameters:
//   - b: a byte slice to be converted to a big.Int.
//   - qLen: an integer representing the desired length.
//
// Returns:
//   - *big.Int: the converted big.Int value.
//
// https://www.rfc-editor.org/rfc/rfc6979 section 2.3.2.
func bitsToInt(b []byte, qLen int) *big.Int {
	bLen := len(b) << 3
	bInt := new(big.Int).SetBytes(b)
	if bLen > qLen {
		bInt.Rsh(bInt, uint(bLen-qLen))
	}
	return bInt
}

// intToOct converts a big.Int to a byte slice of a specified length.
//
// Parameters:
//   - x: The big.Int to convert.
//   - roLen: The desired length of the resulting byte slice.
//
// Returns:
//   - []byte: The byte slice representation of the big.Int.
//
// https://www.rfc-editor.org/rfc/rfc6979 section 2.3.3.
func intToOct(x *big.Int, roLen int) []byte {
	xoLen := x.BitLen() >> 3
	if xoLen < roLen {
		buf := make([]byte, roLen)
		return x.FillBytes(buf)
	}
	if xoLen > roLen {
		buf := make([]byte, xoLen)
		x.FillBytes(buf)
		return buf[xoLen-roLen:]
	}
	return x.Bytes()
}

// bitsToOct converts a byte slice of bits to an octet slice
//
// Parameters:
//   - b: a byte slice representing the bits to be converted
//   - q: a big.Int representing the modulus
//   - qLen: an integer representing the length of the modulus in bits
//   - roLen: an integer representing the desired length of the octet slice in octets
//
// Returns:
//   - a byte slice representing the converted octets
//
// https://www.rfc-editor.org/rfc/rfc6979 section 2.3.4.
func bitsToOct(b []byte, q *big.Int, qLen int, roLen int) []byte {
	var z1, z2 big.Int
	z1.Set(bitsToInt(b, qLen))
	z2.Sub(&z1, q)
	if z2.Cmp(zero) == -1 {
		z2 = z1
	}
	return intToOct(&z2, roLen)
}

// rfcSign generates a signature for a given message using the RFC6979 algorithm.
//
// Parameters:
//   - x: a pointer to a big.Int representing the private key.
//   - msg: a pointer to a big.Int representing the message.
//
// Returns:
//   - *Signature: a pointer to a Signature struct containing the calculated signature.
func rfcSign(x, msg *big.Int) *Signature {
	var (
		q      big.Int
		k      *big.Int
		K_, V_ hash.Hash
		K, V   []byte
		sig    *Signature
	)
	// https://www.rfc-editor.org/rfc/rfc6979 section 3.2.
	q.Set(secp256k1.NCurve)
	qLen := q.BitLen()
	qoLen := qLen >> 3
	roLen := (qLen + 7) >> 3
	// step a is omitted since we already have a hash of a message
	h1 := msg.FillBytes(make([]byte, 32))
	// step b
	V = bytes.Repeat([]byte{0x01}, 32)
	// step c
	K = bytes.Repeat([]byte{0x00}, 32)
	// step d
	mSuffix := joinBytes([][]byte{intToOct(x, roLen), bitsToOct(h1, &q, qLen, roLen)}...)
	m1 := joinBytes([][]byte{{0x00}, mSuffix}...)
	m2 := joinBytes([][]byte{{0x01}, mSuffix}...)
	K_ = hmac.New(sha256.New, K)
	K_.Write(joinBytes([][]byte{V, m1}...))
	K = K_.Sum(nil)
	// step e
	V_ = hmac.New(sha256.New, K)
	V_.Write(V)
	V = V_.Sum(nil)
	// step f
	K_ = hmac.New(sha256.New, K)
	K_.Write(joinBytes([][]byte{V, m2}...))
	K = K_.Sum(nil)
	// step g
	V_ = hmac.New(sha256.New, K)
	V_.Write(V)
	V = V_.Sum(nil)
	// step h
	for {
		var T []byte
		for len(T) < qoLen {
			V_ = hmac.New(sha256.New, K)
			V_.Write(V)
			V = V_.Sum(nil)
			T = joinBytes([][]byte{T, V}...)
		}
		k = bitsToInt(T, qLen)
		if sig = signed(msg, x, k); sig != nil {
			return sig
		}
		// if k was invalid (sig == nil), continue with algorithm
		K_ = hmac.New(sha256.New, K)
		K_.Write(joinBytes([][]byte{V, {0x00}}...))
		K = K_.Sum(nil)
		V_ = hmac.New(sha256.New, K)
		V_.Write(V)
		V = V_.Sum(nil)
	}
}

// deriveAddress generates a Bitcoin address based on the provided public key and address type.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//   - addrType: a string representing the address type. Valid values are "legacy", "nested", and "segwit".
//
// Returns:
//   - a string representing the Bitcoin address.
//   - an integer representing the address type. 0 for legacy, 1 for nested, and 2 for segwit.
//   - an error if the address type is invalid.
func deriveAddress(pubKey []byte, addrType string) (addr string, ver int, err error) {
	prefix := pubKey[0]
	if prefix == 0x04 {
		if addrType != "legacy" {
			return "", 0, &SignatureError{Message: "invalid address type"}
		}
		return createAddress(pubKey), 0, nil
	}
	if addrType == "legacy" {
		return createAddress(pubKey), 1, nil
	}
	if addrType == "nested" {
		return createNestedSegwit(pubKey), 2, nil
	}
	if addrType == "segwit" {
		return createNativeSegwit(pubKey), 3, nil
	}
	return "", 0, &SignatureError{Message: "invalid address type"}

}

// splitSignature splits the given signature byte slice into its header byte and the r and s values.
//
// Parameters:
//   - sig: the signature byte slice to be split.
//
// Returns:
//   - header: the header byte of the signature.
//   - r: a pointer to a big.Int representing the r value of the signature.
//   - s: a pointer to a big.Int representing the s value of the signature.
func splitSignature(sig []byte) (header byte, r, s *big.Int) {
	return sig[0], new(big.Int).SetBytes(sig[1:33]), new(big.Int).SetBytes(sig[33:])
}

// VerifyMessage verifies a signed message using the provided address, message, signature, and electrum flag.
//
// Parameters:
//   - address: the address used to sign the message.
//   - message: the message to be verified.
//   - signature: the signature to verify the message.
//   - electrum: a flag indicating whether to use the electrum signature format.
//
// Returns:
//   - bool: true if the message is verified, false otherwise.
//   - string: the hex-encoded public key.
//   - string: a message indicating whether the message was verified or not.
//   - error: an error if any occurred during the verification process.
func VerifyMessage(message *BitcoinMessage, electrum bool) (verified bool, pubkey string, result string, err error) {
	var (
		x, y, alpha, beta, bt, z, e big.Int
		p, q, Q, pk                 JacobianPoint
	)
	dSig := make([]byte, base64.StdEncoding.DecodedLen(len(message.Signature)))
	n, err := base64.StdEncoding.Decode(dSig, message.Signature)
	if err != nil {
		return false, "", "", &SignatureError{Message: "decode error", Err: err}
	}
	if n != 65 {
		return false, "", "", &SignatureError{Message: "signature must be 65 bytes long"}
	}

	header, r, s := splitSignature(dSig[:n])
	if header < 27 || header > 46 {
		return false, "", "", &SignatureError{Message: "header byte out of range"}
	}
	if r.Cmp(secp256k1.NCurve) >= 0 || r.Cmp(zero) == 0 {
		return false, "", "", &SignatureError{Message: "r-value out of range"}
	}
	if s.Cmp(secp256k1.NCurve) >= 0 || s.Cmp(zero) == 0 {
		return false, "", "", &SignatureError{Message: "s-value out of range"}
	}
	uncompressed := false
	addrType := "legacy"
	if header >= 43 {
		header -= 16
		addrType = ""
	} else if header >= 39 {
		header -= 12
		addrType = "segwit"
	} else if header >= 35 {
		header -= 8
		addrType = "nested"
	} else if header >= 31 {
		header -= 4
	} else {
		uncompressed = true
	}
	recId := big.NewInt(int64(header - 27))
	x.Add(r, x.Mul(secp256k1.NCurve, new(big.Int).Rsh(recId, 1)))
	alpha.Exp(&x, three, nil).Add(&alpha, secp256k1.BCurve).Mod(&alpha, secp256k1.PCurve)
	beta.Exp(&alpha, bt.Add(secp256k1.PCurve, one).Rsh(&bt, 2), secp256k1.PCurve)
	y.Set(&beta)
	if IsOdd(new(big.Int).Sub(&beta, recId)) {
		y.Sub(secp256k1.PCurve, &beta)
	}
	R := NewJacobianPoint(&x, &y, one)
	mBytes := msgMagic(message.Data)
	z.SetBytes(DoubleSHA256(mBytes))
	e.Set(new(big.Int).Neg(&z)).Mod(&e, secp256k1.NCurve)
	p.Mul(s, R)
	q.Mul(&e, secp256k1.GenPoint)
	Q.Add(&p, &q)
	rawPubKey := pk.Mul(ModInverse(r, secp256k1.NCurve), &Q).ToAffine()
	pubKey := createPubKey(rawPubKey, uncompressed)
	if electrum && !uncompressed {
		for _, addrType := range addressTypes {
			addr, _, err := deriveAddress(pubKey, addrType)
			if err != nil {
				return false, "", "", err
			}
			if addr == message.Address {
				return true, hex.EncodeToString(pubKey), fmt.Sprintf("message verified to be from %s", message.Address), nil
			}
		}
		return false, hex.EncodeToString(pubKey), fmt.Sprintln("message failed to verify"), nil
	}
	if addrType == "" {
		return false, "", "", &SignatureError{Message: "unknown address type"}
	}
	addr, _, err := deriveAddress(pubKey, addrType)
	if err != nil {
		panic(err)
	}
	if addr == message.Address {
		return true, hex.EncodeToString(pubKey), fmt.Sprintf("message verified to be from %s", message.Address), nil
	}
	return false, hex.EncodeToString(pubKey), fmt.Sprintln("message failed to verify"), nil
}

// SignMessage generates a Bitcoin message signature using the provided private key, address type, message,
// deterministic flag, and electrum flag.
//
// Parameters:
//   - pk: A pointer to a PrivateKey struct representing the private key.
//     Compressed private key will produce compressed public key and address.
//     Uncompressed private key will only produce one address type - uncompressed legacy address
//   - addrType: A string representing the address type. It can be either p2pkh (compressed and uncompressed),
//     p2wpkh-p2sh or p2wpkh (only compressed).
//   - message: A string representing the message.
//   - deterministic: A boolean indicating whether the signature should be deterministic.
//     If set to true, each unique combination of private key and message will yield only one signature
//   - electrum: A boolean indicating whether the signature should be in Electrum format.
//
// Returns:
//   - A pointer to a BitcoinMessage struct representing the signed message.
//   - An error if there was a problem signing the message.
func SignMessage(pk *PrivateKey, addrType, message string, deterministic, electrum bool) (*BitcoinMessage, error) {
	var (
		r, s, msg     big.Int
		sig           *Signature
		signedMessage BitcoinMessage
	)
	mBytes := msgMagic(message)
	msg.SetBytes(DoubleSHA256(mBytes))
	rawPubKey, err := createRawPubKey(pk.Raw)
	if err != nil {
		return nil, err
	}
	pubKey := createPubKey(rawPubKey, pk.Uncompressed)
	if !deterministic {
		sig = sign(pk.Raw, &msg)
	} else {
		sig = rfcSign(pk.Raw, &msg)
	}
	address, ver, err := deriveAddress(pubKey, addrType)
	if err != nil {
		return nil, err
	}
	if electrum {
		if pk.Uncompressed {
			ver = 0
		} else {
			ver = 1
		}
	}
	buf := make([]byte, 65)
	r.Set(sig.R).FillBytes(buf[1:33])
	s.Set(sig.S).FillBytes(buf[33:])
	for _, header := range headers[ver] {
		buf[0] = header
		signature := make([]byte, base64.StdEncoding.EncodedLen(len(buf)))
		base64.StdEncoding.Encode(signature, buf)
		signedMessage.Address = address
		signedMessage.Data = message
		signedMessage.Signature = signature
		verified, _, _, err := VerifyMessage(&signedMessage, electrum)
		if err != nil {
			return nil, err
		}
		if verified {
			return &signedMessage, nil
		}
	}
	return nil, &SignatureError{Message: "invalid signature parameters"}
}

func printMessage(bm *BitcoinMessage) {
	fmt.Println(beginSignedMessage)
	fmt.Println(bm.Data)
	fmt.Println(beginSignature)
	fmt.Println(bm.Address)
	fmt.Println()
	fmt.Println(string(bm.Signature))
	fmt.Println(endSignature)
}

func trimCRLF(s string) string {
	msg := strings.TrimPrefix(s, "\r")
	msg = strings.TrimPrefix(msg, "\n")
	msg = strings.TrimSuffix(msg, "\r")
	msg = strings.TrimSuffix(msg, "\n")
	return msg
}

func parseRFCMessage(m string) *BitcoinMessage {
	ind1 := strings.Index(m, beginSignedMessage)
	ind2 := strings.Index(m, beginSignature)
	ind3 := strings.Index(m, endSignature)
	if ind1 == -1 || ind2 == -1 || ind3 == -1 {
		return nil
	}
	if ind2 < ind1 || ind3 < ind2 {
		return nil
	}
	partOne := m[ind1+len(beginSignedMessage) : ind2]
	partTwo := m[ind2+len(beginSignature) : ind3]
	message := trimCRLF(partOne)
	signature := strings.Split(trimCRLF(partTwo), "\n")
	return &BitcoinMessage{
		Address:   signature[0],
		Data:      message,
		Signature: []byte(signature[len(signature)-1])}
}

func CreateWallets(n int, path string) {
	var wg sync.WaitGroup
	walletChan := make(chan *Wallet)
	done := make(chan struct{})
	go func() {
		if path == "" {
			for w := range walletChan {
				fmt.Println(w)
			}
		} else {
			f, err := os.OpenFile(filepath.FromSlash(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for w := range walletChan {
				if _, err := f.WriteString(fmt.Sprintln(w)); err != nil {
					f.Close() // ignore error; Write error takes precedence
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}

			}
			if err := f.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		done <- struct{}{}
	}()
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			walletChan <- CreateNewWallet()
		}()
	}
	wg.Wait()
	close(walletChan)
	<-done
}

func NewSignCommand() *SignCommand {
	sc := &SignCommand{
		fs: flag.NewFlagSet("sign", flag.ContinueOnError),
	}
	sc.fs.BoolVar(&sc.help, "h", false, "show this help message and exit")
	sc.fs.BoolVar(&sc.deterministic, "d", false, "sign deterministically (RFC6979)")
	sc.fs.BoolVar(&sc.electrum, "e", false, "create electrum-like signature")
	sc.fs.StringVar(&sc.message, "m", "", "[MESSAGE ...] message to sign")
	sc.fs.BoolFunc("p", "private key in wallet import format (WIF)", func(flagValue string) error {
		fmt.Print("PrivateKey (WIF): ")

		bytepw, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			os.Exit(1)
		}
		pk := string(bytepw)
		sc.pk = pk
		fmt.Println()
		return nil
	})
	sc.fs.Func("a", "type of bitcoin address (legacy, nested, segwit)", func(flagValue string) error {
		flagValue = strings.ToLower(flagValue)
		if !slices.Contains(addressTypes, flagValue) {
			fmt.Fprintf(os.Stderr, "bmt: invalid argument '%s' for -a flag. See 'bmt sign -h'\n", flagValue)
			os.Exit(2)
		}
		sc.addrType = flagValue
		return nil
	})

	return sc
}

type SignCommand struct {
	fs *flag.FlagSet

	help          bool
	pk            string
	addrType      string
	deterministic bool
	electrum      bool
	message       string
}

func (sc *SignCommand) Name() string {
	return sc.fs.Name()
}

func (sc *SignCommand) Init(args []string) error {
	sc.fs.Usage = func() {
		fmt.Println(signUsagePrefix)
		sc.fs.PrintDefaults()
		fmt.Println(signUsageExamples)
	}
	return sc.fs.Parse(args)
}

func (sc *SignCommand) Run() error {
	if sc.help {
		sc.fs.Usage()
		os.Exit(0)
	}
	required := []string{"p", "a", "m"}
	seen := make(map[string]bool)
	sc.fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range required {
		if !seen[req] {
			return fmt.Errorf("bmt: missing required -%s flag. See 'bmt sign -h'", req)
		}
	}
	pk, err := NewPrivateKey(nil, &sc.pk)
	if err != nil {
		return fmt.Errorf("bmt: invalid private key: %w", err)
	}
	bm, err := SignMessage(pk, sc.addrType, sc.message, sc.deterministic, sc.electrum)
	if err != nil {
		return fmt.Errorf("bmt: failed signing message: %w", err)
	}
	printMessage(bm)
	return nil
}

func NewVerifyCommand() *VerifyCommand {
	vc := &VerifyCommand{
		fs: flag.NewFlagSet("verify", flag.ContinueOnError),
	}
	vc.message = &BitcoinMessage{}
	vc.full = false
	vc.fs.BoolVar(&vc.help, "h", false, "show this help message and exit")
	vc.fs.BoolVar(&vc.electrum, "e", false, "verify electrum-like signature")
	vc.fs.BoolVar(&vc.recpub, "r", false, "recover public key")
	vc.fs.BoolVar(&vc.verbose, "v", false, "show full message")
	vc.fs.StringVar(&vc.message.Address, "a", "", "ADDRESS bitcoin address")
	vc.fs.StringVar(&vc.message.Data, "m", "", "[MESSAGE ...] message to verify")
	vc.fs.Func("s", "SIGNATURE bitcoin signature in base64 format", func(flagValue string) error {
		vc.message.Signature = []byte(flagValue)
		return nil
	})
	vc.fs.BoolFunc("f", "verify message in RFC2440-like format", func(flagValue string) error {
		reader := bufio.NewScanner(os.Stdin)
		var lines []string
		fmt.Println("Insert message in RFC2440-like format (or Ctrl+C to quit):")
		for reader.Scan() {
			line := reader.Text()
			lines = append(lines, line)
			if strings.HasPrefix(line, endSignature) {
				break
			}
		}
		message := parseRFCMessage(strings.Join(lines, "\n"))
		if message == nil {
			fmt.Fprintln(os.Stderr, "bmt: failed parsing message")
			os.Exit(2)
		}
		vc.message = message
		vc.full = true
		return nil
	})
	return vc
}

type VerifyCommand struct {
	fs *flag.FlagSet

	help     bool
	electrum bool
	recpub   bool
	verbose  bool
	full     bool
	message  *BitcoinMessage
}

func (vc *VerifyCommand) Name() string {
	return vc.fs.Name()
}

func (vc *VerifyCommand) Init(args []string) error {
	vc.fs.Usage = func() {
		fmt.Println(verifyUsagePrefix)
		vc.fs.PrintDefaults()
		fmt.Println(verifyUsageExamples)
	}
	return vc.fs.Parse(args)
}

func (vc *VerifyCommand) Run() error {
	if vc.help {
		vc.fs.Usage()
		os.Exit(0)
	}
	if !vc.full {
		required := []string{"s", "a", "m"}
		seen := make(map[string]bool)
		vc.fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
		for _, req := range required {
			if !seen[req] {
				return fmt.Errorf("bmt: missing required -%s flag. See 'bmt verify -h'", req)
			}
		}
	}
	verified, pubkey, result, err := VerifyMessage(vc.message, vc.electrum)
	if err != nil {
		return fmt.Errorf("bmt: failed verifying message: %w", err)
	}
	fmt.Println(verified)
	if vc.verbose {
		fmt.Println(result)
	}
	if vc.recpub {
		fmt.Println(pubkey)
	}
	return nil
}

func NewCreateWalletCommand() *CreateWalletCommand {
	cwc := &CreateWalletCommand{
		fs: flag.NewFlagSet("create", flag.ContinueOnError),
	}
	cwc.num = 1
	errMsg := "bmt: values for -n flag should be within the range [1...1000000]"
	cwc.fs.BoolVar(&cwc.help, "h", false, "show this help message and exit")
	cwc.fs.Func("n", "number of wallets to create [1...1000000] (default 1)", func(flagValue string) error {
		i, err := strconv.Atoi(flagValue)
		if err != nil {
			fmt.Fprintln(os.Stderr, errMsg)
			os.Exit(2)
		}
		if i <= 0 || i > 1000000 {
			fmt.Fprintln(os.Stderr, errMsg)
			os.Exit(2)
		}
		cwc.num = i
		return nil
	})
	cwc.fs.StringVar(&cwc.path, "path", "", "path to a file to write created wallets (if ommited prints to stdout)")
	return cwc
}

type CreateWalletCommand struct {
	fs *flag.FlagSet

	help bool
	num  int
	path string
}

func (cwc *CreateWalletCommand) Name() string {
	return cwc.fs.Name()
}

func (cwc *CreateWalletCommand) Init(args []string) error {
	cwc.fs.Usage = func() {
		fmt.Println(createUsagePrefix)
		cwc.fs.PrintDefaults()
		fmt.Println(createUsageExamples)
	}
	return cwc.fs.Parse(args)
}

func (cwc *CreateWalletCommand) Run() error {
	if cwc.help {
		cwc.fs.Usage()
		os.Exit(0)
	}
	CreateWallets(cwc.num, cwc.path)
	return nil
}

type Runner interface {
	Init([]string) error
	Run() error
	Name() string
}

func Root(args []string) error {
	flags.Usage = func() {
		fmt.Println(usagePrefix)
		flags.PrintDefaults()
		fmt.Println(usageCommands)
	}
	flags.Bool("h", false, "show this help message and exit")

	if len(args) < 1 || slices.Contains([]string{"-h", "--h"}, args[0]) {
		flags.Usage()
		os.Exit(0)
	}
	cmds := []Runner{
		NewSignCommand(),
		NewVerifyCommand(),
		NewCreateWalletCommand(),
	}

	subcommand := args[0]

	for _, cmd := range cmds {
		if cmd.Name() == subcommand {
			cmd.Init(os.Args[2:])
			return cmd.Run()
		}
	}
	return fmt.Errorf("bmt: '%s' is not a bmt command. See 'bmt -h'", subcommand)
}
