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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/golangcrypto/ripemd160"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/mr-tron/base58"
	"golang.org/x/term"
)

var (
	flags       = flag.NewFlagSet("bitcoin message tool", flag.ExitOnError)
	usagePrefix = `
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
  create       Create wallet (private key, public key, addresses)
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
Private Key (HEX): 850cece14ffefdb864f6007718a5243dae9194841617c7d6d77b67482d40d856
Private Key (WIF): L1gLtHEKG4FbbxQDzth3ksCZ4jTSjRvcU7K2KDeDE368pG8MjkFg
Public Key (Raw): (X=691ab7d2b2e1b41a8df334a5471a3abd7a93c8822b2abf3de64c552147dc33b8, Y=b1eed621c6b9e790a901ca30eb55ee95d591c3e6dc2e6aa30f2b9f5c525e7e32)
Public Key (HEX Compressed): 02691ab7d2b2e1b41a8df334a5471a3abd7a93c8822b2abf3de64c552147dc33b8
Legacy Address: 1N3kZRUrEioGxXQbSyCWuBwmoFp4T62i93
Nested SegWit Address: 3KWsrxLMHPU1v8riptj33zCsWD8bf6jfLF
Native SegWit Address: bc1qum0at29ayuq2ndk39z4zwf4zdpxv5ker570ape
Taproot Address: bc1p5utaw0g77graev5yw575c3jnzh8j88ezzw39lgr250ghppwpyccsvjkvyp
`
	beginSignedMessage = "-----BEGIN BITCOIN SIGNED MESSAGE-----"
	beginSignature     = "-----BEGIN BITCOIN SIGNATURE-----"
	endSignature       = "-----END BITCOIN SIGNATURE-----"
	order              = NewFieldVal("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	zero               = NewFieldVal("00")
	one                = NewFieldVal("01")
	genPointX          = NewFieldVal("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	genPointY          = NewFieldVal("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	GenPoint           = NewJacobianPoint(genPointX, genPointY, one)
	precomputes        = getPrecomputes()
	IdentityPoint      = NewJacobianPoint(zero, zero, zero)
	addressTypes       = []string{"legacy", "nested", "segwit"}
	headers            = [5][4]byte{
		{0x1b, 0x1c, 0x1d, 0x1e}, // 27 - 30 P2PKH uncompressed
		{0x1f, 0x20, 0x21, 0x22}, // 31 - 34 P2PKH compressed
		{0x23, 0x24, 0x25, 0x26}, // 35 - 38 P2WPKH-P2SH compressed (BIP-137)
		{0x27, 0x28, 0x29, 0x2a}, // 39 - 42 P2WPKH compressed (BIP-137)
		{0x2b, 0x2c, 0x2d, 0x2e}, // TODO 43 - 46 P2TR
	}
	pool = sync.Pool{
		New: func() any {
			s := make([]int, 256)
			return &s
		},
	}
)

type FieldVal = secp256k1.FieldVal
type ModNScalar = secp256k1.ModNScalar

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
	X FieldVal
	Y FieldVal
	Z FieldVal
}

// NewJacobianPoint creates a new JacobianPoint with the given x, y, and z coordinates.
func NewJacobianPoint(x, y, z *FieldVal) *JacobianPoint {
	var p JacobianPoint
	p.X.Set(x)
	p.Y.Set(y)
	p.Z.Set(z)
	return &p
}

// Set sets the Jacobian point to the provided point.
func (p *JacobianPoint) Set(q *JacobianPoint) *JacobianPoint {
	p.X.Set(&q.X)
	p.Y.Set(&q.Y)
	p.Z.Set(&q.Z)
	return p
}

// Eq compares the current JacobianPoint with another JacobianPoint.
//
// Parameters:
//   - q: the JacobianPoint to compare with.
//
// Returns:
//   - bool: true if the points are equal, false otherwise.
func (pt *JacobianPoint) Eq(q *JacobianPoint) bool {
	return pt.X.Equals(&q.X) && pt.Y.Equals(&q.Y) && pt.Z.Equals(&q.Z)
}

// Dbl performs a point doubling operation in the elliptic curve cryptography with 256 Bit Primes.
//
// Parameter:
//   - p: a pointer to a JacobianPoint struct representing the point to be doubled.
//
// Returns:
// A pointer to a JacobianPoint struct representing the result of the point doubling operation.
//
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
func (pt *JacobianPoint) Dbl(p *JacobianPoint) *JacobianPoint {
	if p.Y.IsZero() || p.Z.IsZero() {
		return pt.Set(IdentityPoint)
	}
	var A, B, C, D, E, F, x, y, z FieldVal
	A.SquareVal(&p.X)
	B.SquareVal(&p.Y)
	C.SquareVal(&B)
	B.Add(&p.X).Square()
	D.Set(&A).Add(&C).Negate(2)
	D.Add(&B).MulInt(2)
	E.Set(&A).MulInt(3)
	F.SquareVal(&E)
	x.Set(&D).MulInt(2).Negate(16)
	x.Add(&F)
	F.Set(&x).Negate(18).Add(&D).Normalize()
	y.Set(&C).MulInt(8).Negate(8)
	y.Add(F.Mul(&E))
	if p.Z.IsOne() {
		z.Set(&p.Y).MulInt(2)
	} else {
		z.Mul2(&p.Y, &p.Z).MulInt(2)
	}
	pt.X.Set(x.Normalize())
	pt.Y.Set(y.Normalize())
	pt.Z.Set(z.Normalize())
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
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
func (pt *JacobianPoint) Add(p, q *JacobianPoint) *JacobianPoint {
	if (p.X.IsZero() && p.Y.IsZero()) || p.Z.IsZero() {
		return pt.Set(q)
	}
	if (q.X.IsZero() && q.Y.IsZero()) || q.Z.IsZero() {
		return pt.Set(p)
	}
	var Z1Z1, Z2Z2, U1, U2, S1, S2, x, y, z FieldVal
	Z1Z1.SquareVal(&p.Z)
	Z2Z2.SquareVal(&q.Z)
	U1.Set(&p.X).Mul(&Z2Z2).Normalize()
	U2.Set(&q.X).Mul(&Z1Z1).Normalize()
	S1.Set(&p.Y).Mul(&Z2Z2).Mul(&q.Z).Normalize()
	S2.Set(&q.Y).Mul(&Z1Z1).Mul(&p.Z).Normalize()
	if U1.Equals(&U2) {
		if S1.Equals(&S2) {
			return pt.Dbl(p)
		}
		return pt.Set(IdentityPoint)
	}
	var H, I, J, R, R2, V, negU1, negS1, negX3 FieldVal
	negU1.Set(&U1).Negate(1)
	H.Add2(&U2, &negU1)
	I.Set(&H).MulInt(2).Square()
	J.Mul2(&H, &I)
	negS1.Set(&S1).Negate(1)
	R.Set(&S2).Add(&negS1).MulInt(2)
	R2.SquareVal(&R)
	V.Mul2(&U1, &I)
	x.Set(&V).MulInt(2).Add(&J).Negate(3)
	x.Add(&R2)
	negX3.Set(&x).Negate(5)
	y.Mul2(&S1, &J).MulInt(2).Negate(2)
	y.Add(V.Add(&negX3).Mul(&R))
	z.Add2(&p.Z, &q.Z).Square()
	z.Add(Z1Z1.Add(&Z2Z2).Negate(2))
	z.Mul(&H)

	pt.X.Set(x.Normalize())
	pt.Y.Set(y.Normalize())
	pt.Z.Set(z.Normalize())
	return pt
}

// getPrecomputes generates a slice of JacobianPoints by iteratively doubling a generator point.
func getPrecomputes() []JacobianPoint {
	precomputes := make([]JacobianPoint, 256)
	var p JacobianPoint
	p.Set(GenPoint)
	for i := range len(precomputes) {
		precomputes[i].Set(&p)
		p.Dbl(&p)
	}
	return precomputes
}

// Mul performs elliptic curve multiplication.
//
// It takes two parameters:
//   - scalar: a pointer to a ModNScalar representing the scalar value.
//   - p: a pointer to a JacobianPoint representing the point to be multiplied.
//
// It returns a pointer to a JacobianPoint representing the result of the multiplication.
//
// https://paulmillr.com/posts/noble-secp256k1-fast-ecc/#fighting-timing-attacks
func (pt *JacobianPoint) Mul(scalar *ModNScalar, p *JacobianPoint) *JacobianPoint {
	var pnt, q JacobianPoint
	pnt.Set(IdentityPoint)
	ptr := pool.Get().(*[]int)
	defer pool.Put(ptr)
	scalarBits := *ptr
	bs := scalar.Bytes()
	ConvertToBits(bs[:], &scalarBits)
	if p.Eq(GenPoint) {
		for i, q := range precomputes {
			if scalarBits[i] == 1 {
				pnt.Add(&pnt, &q)
			}
		}
	} else {
		q.Set(p)
		for _, n := range scalarBits {
			if n == 1 {
				pnt.Add(&pnt, &q)
			}
			q.Dbl(&q)
		}
	}
	pt.X.Set(pnt.X.Normalize())
	pt.Y.Set(pnt.Y.Normalize())
	pt.Z.Set(pnt.Z.Normalize())
	return pt
}

// ToAffine converts a point from Jacobian coordinates to affine coordinates.
//
// Parameter:
//   - p: the point in Jacobian coordinates.
//
// Returns:
// A pointer to a Point representing the point in affine coordinates.
func (p *JacobianPoint) ToAffine() *Point {
	if p.Y.IsZero() || p.Z.IsZero() {
		return &Point{X: *p.X.SetInt(0), Y: *p.Y.SetInt(0)}
	}
	var invZ, invZ2 FieldVal
	invZ.Set(&p.Z).Inverse()
	invZ2.SquareVal(&invZ)
	p.X.Mul(&invZ2)
	p.Y.Mul(invZ2.Mul(&invZ))
	p.Z.SetInt(1)
	return &Point{X: *p.X.Normalize(), Y: *p.Y.Normalize()}
}

// String returns a string representation of the JacobianPoint struct.
//
// It returns a string in the format "(x=X=<X>, Y=<Y>, Z=<Z>)", where <X>, <Y> and <Z> are the
// hexadeciaml representations of the X, Y and Z coordinates of the JacobianPoint.
func (pt *JacobianPoint) String() string {
	return fmt.Sprintf("(X=%v, Y=%v, Z=%v)", pt.X, pt.Y, pt.Z)
}

type Point struct {
	X FieldVal
	Y FieldVal
}

// Eq compares the current Point with another Point.
//
// Parameters:
//   - q: the Point to compare with.
//
// Returns:
//   - bool: true if the points are equal, false otherwise.
func (pt *Point) Eq(q *Point) bool {
	return pt.X.Equals(&q.X) && pt.Y.Equals(&q.Y)
}

// String returns a string representation of the Point struct.
//
// It returns a string in the format "(X=<X>, Y=<Y>)", where <X> and <Y> are the
// hexadecimal representations of the X and Y coordinates of the Point.
func (pt *Point) String() string {
	return fmt.Sprintf("(X=%v, Y=%v)", pt.X, pt.Y)
}

// ToJacobian converts a point from affine coordinates to Jacobian coordinates.
//
// Parameter:
//   - p: a pointer to a Point representing the point in affine coordinates.
//
// Returns:
// A pointer to a JacobianPoint representing the point in Jacobian coordinates.
func (pt *Point) ToJacobian() *JacobianPoint {
	return &JacobianPoint{pt.X, pt.Y, *new(FieldVal).SetInt(1)}
}

// Valid checks if a given point is on the elliptic curve.
func (pt *Point) Valid() bool {
	r1 := new(FieldVal).SquareVal(&pt.Y).Normalize()
	r2 := new(FieldVal).SquareVal(&pt.X).Mul(&pt.X).AddInt(7).Normalize()
	return r1.Equals(r2)
}

// NewSignature creates a new signature given some r and s values.
func NewSignature(r, s *ModNScalar) *Signature {
	return &Signature{*r, *s}
}

type Signature struct {
	r ModNScalar
	s ModNScalar
}

// R returns the r value of the signature.
func (sig *Signature) R() ModNScalar {
	return sig.r
}

// S returns the s value of the signature.
func (sig *Signature) S() ModNScalar {
	return sig.s
}

type BitcoinMessage struct {
	Address   string
	Data      string
	Signature []byte
}

type VerifyMessageResult struct {
	Verified bool
	PubKey   string
	Message  string
}

type privatekey struct {
	raw          *ModNScalar
	wif          *string
	uncompressed bool
}

// generate generates a random value within the range of the secp256k1 group order.
func generate() *ModNScalar {
	buf := make([]byte, 32)
	for {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		if scalar, ok := ValidateKey(&buf); ok {
			return scalar
		}
	}

}

// NewPrivateKey generates a new privatekey object.
//
// It takes in two parameters:
//   - raw: a pointer to a byte slice object representing the raw value of the private key.
//   - wif: a pointer to a string representing the WIF (Wallet Import Format) of the private key.
//
// The function returns a pointer to a privatekey object and an error.
//
//   - If both raw and wif are provided, it returns an error.
//   - If neither raw nor wif is provided, it generates a random private key and returns a new privatekey object.
//   - If only wif is provided, it creates a new privatekey object with the provided WIF.
//   - If only raw is provided, it creates a new privatekey object with the provided raw value.
//
// The function checks if the generated or provided private key is valid.
// If the private key is invalid, it returns an error.
//
// The function also encodes the generated or provided private key using the ToWif() method.
// If the encoding fails, it returns an error.
//
// The function returns a pointer to the newly created privatekey object.
func NewPrivateKey(raw *[]byte, wif *string) (*privatekey, error) {
	var pk privatekey
	if raw != nil && wif != nil {
		return nil, &PrivateKeyError{Message: "cannot specify both raw and wif"}
	}
	if raw == nil && wif == nil {
		pk.raw = generate()
		pk.uncompressed = false
		encoded, _ := pk.hexToWif(pk.uncompressed)
		pk.wif = encoded
	} else if wif == nil {
		scalar, ok := ValidateKey(raw)
		if !ok {
			return nil, &PrivateKeyError{Message: "scalar is out of range"}
		}
		pk.raw = scalar
		pk.uncompressed = false
		encoded, _ := pk.hexToWif(pk.uncompressed)
		pk.wif = encoded
	} else if raw == nil {
		pk.wif = wif
		uncompressed, err := pk.wifToHex()
		if err != nil {
			return nil, err
		}
		pk.uncompressed = uncompressed
	}
	return &pk, nil
}

// Hex returns the hexadecimal representation of the private key.
func (k *privatekey) Hex() *ModNScalar {
	return k.raw
}

// Wif returns the WIF (Wallet Import Format) representation of the private key.
func (k *privatekey) Wif() string {
	return *k.wif
}

// IsCompressed returns a boolean indicating whether the private key is compressed.
func (k *privatekey) IsCompressed() bool {
	return !k.uncompressed
}

// splitBytes splits the private key bytes into three parts: the version byte, the private key bytes, and the checksum bytes.
//
// It takes no parameters.
// It returns three byte slices: the version byte, the private key bytes, and the checksum bytes.
func (k *privatekey) splitBytes() (version []byte, payload []byte, checkSum []byte, err error) {
	privkey, err := base58.Decode(*k.wif)
	if err != nil {
		return nil, nil, nil, err
	}
	pkLen := len(privkey)
	if pkLen-4 < 1 {
		return nil, nil, nil, &PrivateKeyError{Message: "too short"}
	}
	return privkey[:1], privkey[1 : pkLen-4], privkey[pkLen-4:], nil
}

// wifToHex creates a hexadecimal representation of the private key.
//
// It returns a boolean indicating if the key is uncompressed and an error if any.
func (k *privatekey) wifToHex() (uncompressed bool, err error) {

	if k.wif == nil {
		return false, &PrivateKeyError{Message: "wif cannot be empty"}
	}
	version, priVkey, checkSum, err := k.splitBytes()
	if err != nil {
		return false, &PrivateKeyError{Message: "failed decoding wif string", Err: err}
	}
	if !validChecksum(version, priVkey, checkSum) {
		return false, &PrivateKeyError{Message: "invalid wif checksum"}
	}

	var privKeyBytes []byte
	if len(priVkey) == 33 {
		privKeyBytes = priVkey[:len(priVkey)-1]
		uncompressed = false
	} else {
		privKeyBytes = priVkey
		uncompressed = true
	}
	scalar, ok := ValidateKey(&privKeyBytes)
	if !ok {
		return false, &PrivateKeyError{Message: "scalar is out of range"}
	}
	k.raw = scalar
	return uncompressed, nil
}

// hexToWif generates the Wallet Import Format (WIF) for the private key.
//
// It takes a boolean uncompressed indicating if the key is uncompressed.
// It returns a pointer to a string and an error.
func (k *privatekey) hexToWif(uncompressed bool) (*string, error) {
	if k.raw == nil {
		return nil, &PrivateKeyError{Message: "scalar is out of range"}
	}
	pkBytes := k.raw.Bytes()
	pk := joinBytesFixed(34, []byte{0x80}, pkBytes[:], []byte{0x01})
	if uncompressed {
		pk = pk[:len(pk)-1]
	}
	converted := base58.Encode(joinBytesFixed(len(pk)+4, pk, checkSum(pk)))
	k.wif = &converted
	return k.wif, nil
}

// CreateNewWallet generates a new wallet with private key, public key, and various address types.
//
// Parameters:
//
//   - raw: a pointer to a byte slice object representing the raw value of the private key.
//   - wif: a pointer to a string representing the WIF (Wallet Import Format) of the private key.
//
// Returns:
//   - A pointer to a wallet struct representing the new wallet.
//   - An error if any occurred during the generation process.
//
// If both parameters are nil generates a random wallet
func CreateNewWallet(raw *[]byte, wif *string) (*wallet, error) {
	var nestedAddress, nativeAddress, taprootAddress string
	privKey, err := NewPrivateKey(raw, wif)
	if err != nil {
		return nil, err
	}
	rawPubKey, err := createRawPubKey(privKey.raw)
	if err != nil {
		panic(err)
	}
	pubKey := createPubKey(rawPubKey, privKey.uncompressed)
	legacyAddress := createAddress(pubKey)
	if !privKey.uncompressed {
		nestedAddress = createNestedSegwit(pubKey)
		nativeAddress = createNativeSegwit(pubKey)
		taprootAddress = createTaproot(createTweakedPubKey(rawPubKey))
	}
	return &wallet{privKey: privKey,
		rawPubKey: rawPubKey,
		pubKey:    hex.EncodeToString(pubKey),
		legacy:    legacyAddress,
		nested:    nestedAddress,
		native:    nativeAddress,
		taproot:   taprootAddress}, nil
}

type wallet struct {
	privKey   *privatekey
	rawPubKey *Point
	pubKey    string
	legacy    string
	nested    string
	native    string
	taproot   string
}

// String returns a formatted string representation of the wallet.
//
// It concatenates the private key (hex), private key (WIF), public key (raw),
// public key (hex compressed) and addresses into a single string.
//
// Returns:
//   - A string containing the formatted representation of the wallet.
func (w *wallet) String() string {
	return fmt.Sprintf(`Private Key (HEX): %s
Private Key (WIF): %s
Public Key (Raw): %s
Public Key (HEX Compressed): %s
Legacy Address: %s
Nested SegWit Address: %s
Native SegWit Address: %s
Taproot Address: %s
`, w.privKey.raw, *w.privKey.wif, w.rawPubKey, w.pubKey, w.legacy, w.nested, w.native, w.taproot)
}

// PrivateKey returns the private key of the wallet.
func (w *wallet) PrivateKey() *privatekey {
	return w.privKey
}

// PublicKeyRaw returns the raw public key of the wallet.
func (w *wallet) PublicKeyRaw() *Point {
	return w.rawPubKey
}

// PublicKey returns the public key of the wallet.
func (w *wallet) PublicKey() string {
	return w.pubKey
}

// LegacyAddress returns the legacy address (P2PKH) of the wallet.
func (w *wallet) LegacyAddress() string {
	return w.legacy
}

// NestedSegwitAddress returns the nested SegWit address (P2WPKH-P2SH) of the wallet.
//
// Returns empty string if wallet created from WIF-uncompressed private key
func (w *wallet) NestedSegwitAddress() string {
	return w.nested
}

// SegwitAddress returns the native SegWit address (P2WPKH) of the wallet.
//
// Returns empty string if wallet created from WIF-uncompressed private key
func (w *wallet) SegwitAddress() string {
	return w.native
}

// TaprootAddress returns the Taproot Bitcoin address of the wallet.
//
// Returns empty string if wallet created from WIF-uncompressed private key
func (w *wallet) TaprootAddress() string {
	return w.taproot
}

// ConvertToBits converts scalar bytes into a little-endian bit array.
//
// Parameters:
//   - scalar: bytes slice representing the scalar value to convert.
//   - buf: a pointer to a slice of integers representing the bit array.
//
// Returns:
//   - The function does not return anything. The bit array is stored in the slice pointed to by the buf parameter.
//
// If the bit length of scalar doesn't fit in buf, ConvertToBits will panic.
func ConvertToBits(scalar []byte, buf *[]int) {
	r := *buf
	scalarlen := len(scalar)
	if len(r) < scalarlen*8 {
		panic("buffer too small to fit value")
	}
	for i := scalarlen - 1; i >= 0; i-- {
		for j := 7; j >= 0; j-- {
			r[(scalarlen-1-i)*8+j] = int(scalar[i] >> uint(j) & 0x01)
		}
	}
	*buf = r
}

// NewFieldVal creates a new FieldVal object from a hexadecimal string.
//
// Parameters:
//   - s: a string representing the hexadecimal value.
//
// Returns:
//   - A pointer to a FieldVal object.
func NewFieldVal(s string) *FieldVal {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	var fv FieldVal
	fv.SetByteSlice(bs)
	return &fv
}

// NewModNScalar creates a new ModNScalar object from a hexadecimal string.
//
// Parameters:
//   - s: a string representing the hexadecimal value.
//
// Returns:
//   - A pointer to a ModNScalar object.
func NewModNScalar(s string) *ModNScalar {
	var scalar ModNScalar
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	scalar.SetByteSlice(bs)
	return &scalar
}

// NewStr returns a pointer to the input string.
//
// Parameters:
//   - s: a string.
//
// Returns:
//   - *string: a pointer to the input string.
func NewStr(s string) *string {
	return &s
}

// NewByteStr decodes a hexadecimal string into a byte slice and returns a pointer to it.
//
// Parameters:
//   - s: a string representing the hexadecimal value.
//
// Returns:
//   - *[]byte: a pointer to the decoded byte slice.
func NewByteStr(s string) *[]byte {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return &bs
}

// ValidateKey checks if the given ModNScalar is a valid key.
//
// Parameters:
//   - b: a pointer to a byte slice representing the raw private key.
//
// Returns:
//   - *ModNScalar: a pointer to a ModNScalar object if the scalar is not zero, nil otherwise.
//   - bool: true if the scalar is not zero, false otherwise.
func ValidateKey(b *[]byte) (*ModNScalar, bool) {
	var scalar ModNScalar
	if b == nil {
		return nil, false
	}
	overflow := scalar.SetByteSlice(*b)
	if overflow || scalar.IsZero() {
		return nil, false
	}
	return &scalar, true
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
// The Ripemd160 hashed byte slice.
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
func joinBytes(bs ...[]byte) []byte {
	n := 0
	for _, v := range bs {
		n += len(v)
	}
	b, i := make([]byte, n), 0
	for _, v := range bs {
		i += copy(b[i:], v)
	}
	return b
}

// joinBytesFixed concatenates the byte slices in s into a single byte slice of a fixed size.
//
// Parameters:
//   - size: the fixed size of the resulting byte slice.
//   - bs: variadic parameter containing byte slices to be concatenated.
//
// Returns a byte slice of the specified size.
func joinBytesFixed(size int, bs ...[]byte) []byte {
	b, i := make([]byte, size), 0
	for _, v := range bs {
		i += copy(b[i:], v)
	}
	return b
}

// createRawPubKey generates a raw public key from a given private key.
//
// Parameters:
//   - privKey: a pointer to a ModNScalar representing the private key.
//
// Returns:
//   - a pointer to a Point representing the raw public key.
//   - an error if the generated point is not on the curve.
func createRawPubKey(privKey *ModNScalar) (*Point, error) {
	var p JacobianPoint
	rawPubKey := p.Mul(privKey, GenPoint).ToAffine()
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
	if uncompressed {
		return joinBytesFixed(65, []byte{0x04}, rawPubKey.X.Bytes()[:], rawPubKey.Y.Bytes()[:])
	}
	prefix := []byte{0x02}
	if rawPubKey.Y.IsOdd() {
		prefix = []byte{0x03}
	}
	return joinBytesFixed(33, prefix, rawPubKey.X.Bytes()[:])
}

// calculateTweak generates a tweak value for a given raw public key.
//
// Parameters:
//   - rawPubKey: a pointer to a Point representing the raw public key.
//
// Returns:
//   - a pointer to a ModNScalar representing the tweak value.
//
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
func calculateTweak(rawPubKey *Point) *ModNScalar {
	var tweak ModNScalar
	h1 := sha256.New()
	h2 := sha256.New()
	h1.Write([]byte("TapTweak"))
	h2.Write(joinBytesFixed(96, h1.Sum(nil), h1.Sum(nil), rawPubKey.X.Bytes()[:]))
	tweak.SetByteSlice(h2.Sum(nil))
	return &tweak
}

// createTweakedPubKey generates a tweaked public key from a given raw public key.
//
// Parameters:
//   - rawPubKey: a pointer to a Point representing the raw public key.
//
// Returns:
//   - a byte slice representing the tweaked public key.
//
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
func createTweakedPubKey(rawPubKey *Point) []byte {
	var q JacobianPoint
	tweak := calculateTweak(rawPubKey)
	p := &Point{X: *new(FieldVal).Set(&rawPubKey.X), Y: *new(FieldVal).Set(&rawPubKey.Y)}
	if p.Y.IsOdd() {
		p.Y.Negate(1)
	}
	q.Add(p.ToJacobian(), q.Mul(tweak, GenPoint))
	qa := q.ToAffine()
	if qa.Y.IsOdd() {
		qa.Y.Negate(1)
	}
	return createPubKey(qa, false)[1:]
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

func validChecksum(ver, privKey, checkSum []byte) bool {
	return bytes.Equal(DoubleSHA256(joinBytes(ver, privKey))[:4], checkSum)
}

// createAddress generates a Bitcoin address from a given public key.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//
// Returns:
//   - a string representing the Bitcoin address.
func createAddress(pubKey []byte) string {
	address := joinBytesFixed(21, []byte{0x00}, Ripemd160SHA256(pubKey))
	return base58.Encode(joinBytesFixed(25, address, checkSum(address)))
}

// createNestedSegwit generates a nested SegWit Bitcoin address from a given public key.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//
// Returns:
//   - a string representing the nested SegWit Bitcoin address.
func createNestedSegwit(pubKey []byte) string {
	address := joinBytesFixed(21, []byte{0x05}, Ripemd160SHA256(joinBytesFixed(22, []byte{0x00, 0x14}, Ripemd160SHA256(pubKey))))
	return base58.Encode(joinBytesFixed(25, address, checkSum(address)))
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

// createTaproot generates a Taproot Bitcoin address from a given public key.
//
// Parameters:
//   - pubKey: a byte slice representing the public key.
//
// Returns:
//   - a string representing the Taproot Bitcoin address.
func createTaproot(pubKey []byte) string {
	converted, err := bech32.ConvertBits(pubKey, 8, 5, true)
	if err != nil {
		panic(err)
	}
	combined := make([]byte, len(converted)+1)
	combined[0] = byte(1)
	copy(combined[1:], converted)
	addr, err := bech32.EncodeM("bc", combined)
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
	buf := make([]byte, 9)
	buf[0] = prefix
	binary.LittleEndian.PutUint64(buf[1:], length)
	return buf[:lenBytes+1]
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
	return joinBytes([]byte{0x18}, []byte("Bitcoin Signed Message:\n"), varInt(uint64(len(message))), message)
}

// signed calculates the signature of a message using the provided private key.
//
// Parameters:
//   - msg: a hash of a signature (usually double sha256 of a message with 'msgMagic' applied).
//   - privKey: a pointer to a ModNScalar representing the private key.
//   - k: nonce that comes from random (SystemRandom) or pseudorandom source (RFC6979).
//
// Returns:
//   - *Signature: a pointer to a Signature struct containing the calculated signature components.
func signed(msg []byte, privKey, k *ModNScalar) *Signature {
	var (
		r, s, e, kinv ModNScalar
		p             JacobianPoint
		buf           [32]byte
	)
	point := p.Mul(k, GenPoint).ToAffine()
	point.X.PutBytes(&buf)
	r.SetBytes(&buf)
	if r.IsZero() {
		return nil
	}
	e.SetByteSlice(msg)
	kinv.InverseValNonConst(k)
	s.Mul2(privKey, &r).Add(&e).Mul(&kinv)
	if s.IsZero() {
		return nil
	}
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	return NewSignature(&r, &s)
}

// sign generates a signature based on the provided private key and message.
//
// Parameters:
//   - msg: a hash of a signature (usually double sha256 of a message with 'msgMagic' applied).
//   - privKey: a pointer to a ModNScalar representing the private key.
//
// Returns:
//   - *Signature: a pointer to a Signature struct containing the generated signature.
//
// https://learnmeabitcoin.com/technical/ecdsa#sign
func sign(msg []byte, privKey *ModNScalar) *Signature {
	var (
		k   *ModNScalar
		sig *Signature
	)
	for {
		k = generate()
		sig = signed(msg, privKey, k)
		if sig != nil {
			return sig
		}
	}
}

// rfcSign generates a signature for a given message using the RFC6979 algorithm.
//
// Parameters:
//   - msg: a byte slice representing the message.
//   - privKey: a pointer to a ModNScalar representing the private key.
//
// Returns:
//   - *Signature: a pointer to a Signature struct containing the calculated signature.
func rfcSign(msg []byte, privKey *ModNScalar) *Signature {
	const (
		privKeyLen = 32
		msgLen     = 32
	)
	var keyBuf [privKeyLen + msgLen]byte
	// https://www.rfc-editor.org/rfc/rfc6979 section 3.2.
	var pb [32]byte
	privKey.PutBytes(&pb)
	privKeyBytes := pb[:]
	if len(privKeyBytes) > privKeyLen {
		privKeyBytes = privKeyBytes[:privKeyLen]
	}
	if len(msg) > msgLen {
		msg = msg[:msgLen]
	}
	offset := privKeyLen - len(privKeyBytes)
	offset += copy(keyBuf[offset:], privKeyBytes)
	offset += msgLen - len(msg)
	offset += copy(keyBuf[offset:], msg)

	key := keyBuf[:offset]
	// step a is omitted since we already have a hash of a message
	// step b
	V := bytes.Repeat([]byte{0x01}, 32)
	// step c
	K := bytes.Repeat([]byte{0x00}, 32)
	// step d
	K_ := hmac.New(sha256.New, K)
	K_.Write(joinBytesFixed(33+len(key), V, []byte{0x00}, key))
	K = K_.Sum(nil)
	// step e
	V_ := hmac.New(sha256.New, K)
	V_.Write(V)
	V = V_.Sum(nil)
	// step f
	K_ = hmac.New(sha256.New, K)
	K_.Write(joinBytesFixed(33+len(key), V, []byte{0x01}, key))
	K = K_.Sum(nil)
	// step g
	V_ = hmac.New(sha256.New, K)
	V_.Write(V)
	V = V_.Sum(nil)
	// step h
	for {
		V_ = hmac.New(sha256.New, K)
		V_.Write(V)
		V = V_.Sum(nil)
		if k, ok := ValidateKey(&V); ok {
			if sig := signed(msg, privKey, k); sig != nil {
				return sig
			}
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
//   - r: a pointer to a ModNScalar representing the r value of the signature.
//   - s: a pointer to a ModNScalar representing the s value of the signature.
func splitSignature(sig []byte) (byte, *ModNScalar, *ModNScalar, error) {
	header := sig[0]
	if header < headers[0][0] || header > headers[4][3] {
		return 0, nil, nil, &SignatureError{Message: "header byte out of range"}
	}
	var (
		overflow bool
		r        ModNScalar
	)
	overflow = r.SetByteSlice(sig[1:33])
	if overflow || r.IsZero() {
		return 0, nil, nil, &SignatureError{Message: "r-value out of range"}
	}
	var s ModNScalar
	overflow = s.SetByteSlice(sig[33:])
	if overflow || s.IsZero() {
		return 0, nil, nil, &SignatureError{Message: "s-value out of range"}
	}
	return header, &r, &s, nil
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
//   - a pointer to a VerifyMessageResult struct containing the verification result and the hex-encoded public key.
//   - error: an error if any occurred during the verification process.
func VerifyMessage(message *BitcoinMessage, electrum bool) (*VerifyMessageResult, error) {
	dsig := make([]byte, base64.StdEncoding.DecodedLen(len(message.Signature)))
	n, err := base64.StdEncoding.Decode(dsig, message.Signature)
	if err != nil {
		return nil, &SignatureError{Message: "decode error", Err: err}
	}
	if n != 65 {
		return nil, &SignatureError{Message: "signature must be 65 bytes long"}
	}
	header, r, s, err := splitSignature(dsig[:n])
	if err != nil {
		return nil, err
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
	recId := header - 27
	var buf [32]byte
	r.PutBytes(&buf)
	var R FieldVal
	R.SetBytes(&buf)
	if recId&2 != 0 {
		if R.IsGtOrEqPrimeMinusOrder() {
			return nil, &SignatureError{Message: "invalid signature: signature R + N >= P"}
		}
		R.Add(order)
	}
	oddY := recId&1 != 0
	var y FieldVal
	if valid := secp256k1.DecompressY(&R, oddY, &y); !valid {
		return nil, &SignatureError{Message: "invalid signature: not for a valid curve point"}
	}
	var X JacobianPoint
	X.X.Set(R.Normalize())
	X.Y.Set(y.Normalize())
	X.Z.SetInt(1)
	var e ModNScalar
	e.SetByteSlice(DoubleSHA256(msgMagic(message.Data)))
	w := new(ModNScalar).InverseValNonConst(r)
	u1 := new(ModNScalar).Mul2(&e, w).Negate()
	u2 := new(ModNScalar).Mul2(s, w)
	var Q, u1G, u2X JacobianPoint
	u1G.Mul(u1, GenPoint)
	u2X.Mul(u2, &X)
	Q.Add(&u1G, &u2X)
	if Q.Eq(IdentityPoint) {
		return nil, &SignatureError{Message: "invalid signature: recovered pubkey is the point at infinity"}
	}
	pubKey := createPubKey(Q.ToAffine(), uncompressed)
	if electrum && !uncompressed {
		for _, addrType := range addressTypes {
			addr, _, err := deriveAddress(pubKey, addrType)
			if err != nil {
				return nil, err
			}
			if addr == message.Address {
				return &VerifyMessageResult{
					Verified: true,
					PubKey:   hex.EncodeToString(pubKey),
					Message:  fmt.Sprintf("message verified to be from %s", message.Address)}, nil
			}
		}
		return &VerifyMessageResult{
			Verified: false,
			PubKey:   hex.EncodeToString(pubKey),
			Message:  "message failed to verify"}, nil
	}
	if addrType == "" {
		return nil, &SignatureError{Message: "unknown address type"}
	}
	addr, _, err := deriveAddress(pubKey, addrType)
	if err != nil {
		return nil, err
	}
	if addr == message.Address {
		return &VerifyMessageResult{
			Verified: true,
			PubKey:   hex.EncodeToString(pubKey),
			Message:  fmt.Sprintf("message verified to be from %s", message.Address)}, nil
	}
	return &VerifyMessageResult{
		Verified: false,
		PubKey:   hex.EncodeToString(pubKey),
		Message:  "message failed to verify"}, nil
}

// SignMessage generates a Bitcoin message signature using the provided private key, address type, message,
// deterministic flag, and electrum flag.
//
// Parameters:
//   - pk: A pointer to a privatekey struct representing the private key.
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
func SignMessage(pk *privatekey, addrType, message string, deterministic, electrum bool) (*BitcoinMessage, error) {
	var (
		sig           *Signature
		signedMessage BitcoinMessage
	)
	msg := DoubleSHA256(msgMagic(message))
	rawPubKey, err := createRawPubKey(pk.raw)
	if err != nil {
		panic(err)
	}
	pubKey := createPubKey(rawPubKey, pk.uncompressed)
	if !deterministic {
		sig = sign(msg, pk.raw)
	} else {
		sig = rfcSign(msg, pk.raw)
	}
	address, ver, err := deriveAddress(pubKey, addrType)
	if err != nil {
		return nil, err
	}
	if electrum {
		if pk.uncompressed {
			ver = 0
		} else {
			ver = 1
		}
	}
	var buf [65]byte
	sig.r.PutBytesUnchecked(buf[1:33])
	sig.s.PutBytesUnchecked(buf[33:65])
	for _, header := range headers[ver] {
		buf[0] = header
		signature := make([]byte, base64.StdEncoding.EncodedLen(len(buf)))
		base64.StdEncoding.Encode(signature, buf[:])
		signedMessage.Address = address
		signedMessage.Data = message
		signedMessage.Signature = signature
		result, err := VerifyMessage(&signedMessage, electrum)
		if err != nil {
			return nil, err
		}
		if result.Verified {
			return &signedMessage, nil
		}
	}
	return nil, &SignatureError{Message: "invalid signature parameters"}
}

// PrintMessage prints signed message in RFC2440-like format
//
// https://datatracker.ietf.org/doc/html/rfc2440
func PrintMessage(bm *BitcoinMessage) {
	fmt.Println(beginSignedMessage)
	fmt.Println(bm.Data)
	fmt.Println(beginSignature)
	fmt.Println(bm.Address)
	fmt.Println()
	fmt.Println(string(bm.Signature))
	fmt.Println(endSignature)
}

// trimCRLF removes leading and trailing carriage return and line feed characters from the input string.
func trimCRLF(s string) string {
	msg := strings.TrimPrefix(s, "\r")
	msg = strings.TrimPrefix(msg, "\n")
	msg = strings.TrimSuffix(msg, "\r")
	msg = strings.TrimSuffix(msg, "\n")
	return msg
}

// // ParseRFCMessage parses a given message (RFC2440-like format) string into a BitcoinMessage struct.
// //
// // Parameters:
// //   - m: a string representing the message to be parsed.
// //
// // Returns:
// //   - *BitcoinMessage: a pointer to a BitcoinMessage struct containing the parsed message data.
func ParseRFCMessage(m string) *BitcoinMessage {
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

// CreateWallets generates a specified number of wallets and either prints them to stdout or writes them to a file.
//
// Parameters:
//   - n: the number of wallets to generate.
//   - path: the path to the file where the wallets should be written. If empty, the wallets will be printed to stdout.
func CreateWallets(n int, path string) {
	var wg sync.WaitGroup
	jobs := make(chan struct{}, runtime.NumCPU())
	walletChan := make(chan *wallet)
	done := make(chan struct{})
	go func() {
		if path == "" {
			for w := range walletChan {
				os.Stdout.WriteString(w.String() + "\n")
			}
		} else {
			f, err := os.OpenFile(filepath.FromSlash(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for w := range walletChan {
				if _, err := f.WriteString(w.String() + "\n"); err != nil {
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
			jobs <- struct{}{}
			w, _ := CreateNewWallet(nil, nil)
			walletChan <- w
			<-jobs
		}()
	}
	wg.Wait()
	close(walletChan)
	<-done
}

func newCmdSign() *cmdSign {
	sc := &cmdSign{
		fs: flag.NewFlagSet("sign", flag.ContinueOnError),
	}
	sc.fs.BoolVar(&sc.help, "h", false, "show this help message and exit")
	sc.fs.BoolVar(&sc.deterministic, "d", false, "sign deterministically (RFC6979)")
	sc.fs.BoolVar(&sc.electrum, "e", false, "create electrum-like signature")
	sc.fs.StringVar(&sc.message, "m", "", "[MESSAGE ...] message to sign")
	sc.fs.BoolFunc("p", "private key in wallet import format (WIF)", func(flagValue string) error {
		fmt.Print("PrivateKey (WIF): ")

		bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			os.Exit(1)
		}
		sc.pk = string(bytepw)
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

type cmdSign struct {
	fs *flag.FlagSet

	help          bool
	pk            string
	addrType      string
	deterministic bool
	electrum      bool
	message       string
}

func (sc *cmdSign) Name() string {
	return sc.fs.Name()
}

func (sc *cmdSign) Init(args []string) error {
	sc.fs.Usage = func() {
		fmt.Println(signUsagePrefix)
		sc.fs.PrintDefaults()
		fmt.Println(signUsageExamples)
	}
	return sc.fs.Parse(args)
}

func (sc *cmdSign) Run() error {
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
	PrintMessage(bm)
	return nil
}

func newCmdVerify() *cmdVerify {
	vc := &cmdVerify{
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
		message := ParseRFCMessage(strings.Join(lines, "\n"))
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

type cmdVerify struct {
	fs *flag.FlagSet

	help     bool
	electrum bool
	recpub   bool
	verbose  bool
	full     bool
	message  *BitcoinMessage
}

func (vc *cmdVerify) Name() string {
	return vc.fs.Name()
}

func (vc *cmdVerify) Init(args []string) error {
	vc.fs.Usage = func() {
		fmt.Println(verifyUsagePrefix)
		vc.fs.PrintDefaults()
		fmt.Println(verifyUsageExamples)
	}
	return vc.fs.Parse(args)
}

func (vc *cmdVerify) Run() error {
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
	result, err := VerifyMessage(vc.message, vc.electrum)
	if err != nil {
		return fmt.Errorf("bmt: failed verifying message: %w", err)
	}
	fmt.Println(result.Verified)
	if vc.verbose {
		fmt.Println(result.Message)
	}
	if vc.recpub {
		fmt.Println(result.PubKey)
	}
	return nil
}

func newCmdCreateWallet() *cmdCreateWallet {
	cwc := &cmdCreateWallet{
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

type cmdCreateWallet struct {
	fs *flag.FlagSet

	help bool
	num  int
	path string
}

func (cwc *cmdCreateWallet) Name() string {
	return cwc.fs.Name()
}

func (cwc *cmdCreateWallet) Init(args []string) error {
	cwc.fs.Usage = func() {
		fmt.Println(createUsagePrefix)
		cwc.fs.PrintDefaults()
		fmt.Println(createUsageExamples)
	}
	return cwc.fs.Parse(args)
}

func (cwc *cmdCreateWallet) Run() error {
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

// Root is an entrypoint to bmt CLI application
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
		newCmdSign(),
		newCmdVerify(),
		newCmdCreateWallet(),
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
