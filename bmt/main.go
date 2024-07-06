package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/golangcrypto/ripemd160"
	"github.com/mr-tron/base58"
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
	addressTypes  = [3]string{"p2pkh", "p2wpkh-p2sh", "p2wpkh"}
)

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

type Point struct {
	X *big.Int
	Y *big.Int
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

// Generate generates a random big.Int value within the range of secp256k1.NCurve.
//
// It returns a pointer to a big.Int value.
func Generate() *big.Int {
	if n, err := rand.Int(rand.Reader, secp256k1.NCurve); err != nil {
		panic(err)
	} else {
		return n
	}
}

// ValidKey checks if the given big.Int scalar is a valid key.
//
// Parameters:
//   - scalar: a pointer to a big.Int representing the scalar value.
//
// Returns:
//   - bool: true if the scalar is valid, false otherwise.
func ValidKey(scalar *big.Int) bool {
	return scalar.Cmp(zero) == 1 && scalar.Cmp(secp256k1.NCurve) == -1
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
		return nil, errors.New("point is not on curve")
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
	buf := make([]byte, 32)
	if uncompressed {
		return joinBytes([][]byte{{0x04}, rawPubKey.X.FillBytes(buf), rawPubKey.Y.FillBytes(buf)}...)
	}
	if IsOdd(rawPubKey.Y) {
		prefix = 0x03
	} else {
		prefix = 0x02
	}
	return joinBytes([][]byte{{prefix}, rawPubKey.X.FillBytes(buf)}...)
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
func createNativeSegwit(pubKey []byte) (string, error) {
	converted, err := bech32.ConvertBits(Ripemd160SHA256(pubKey), 8, 5, true)
	if err != nil {
		return "", err
	}
	combined := make([]byte, len(converted)+1)
	combined[0] = byte(0)
	copy(combined[1:], converted)
	return bech32.Encode("bc", combined)
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
func signed(privKey, msg, k *big.Int) *Signature {
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
		sig *Signature
	)
	for {
		k = Generate()
		sig = signed(privKey, msg, k)
		if sig != nil {
			return sig
		}
	}
}

func deriveAddress(pubKey []byte, addrType string) (string, int, error) {
	prefix := pubKey[0]
	if prefix == 0x04 {
		if addrType != "p2pkh" {
			return "", 0, errors.New("empty")
		}
		return createAddress(pubKey), 0, nil
	}
	if addrType == "p2pkh" {
		return createAddress(pubKey), 1, nil
	}
	if addrType == "p2wpkh-p2sh" {
		return createNestedSegwit(pubKey), 2, nil
	}
	if addrType == "p2wpkh" {
		if addr, err := createNativeSegwit(pubKey); err != nil {
			return "", 0, err
		} else {
			return addr, 3, nil
		}
	}
	return "", 0, errors.New("invalid address type")

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
func VerifyMessage(address, message, signature string, electrum bool) (bool, string, string, error) {
	var (
		x, y, alpha, beta, bt, z, e big.Int
		p, q, Q, pk                 JacobianPoint
	)
	dSig := make([]byte, base64.StdEncoding.DecodedLen(len(signature)))
	n, err := base64.StdEncoding.Decode(dSig, []byte(signature))
	if err != nil {
		fmt.Println("decode error:", err)
		return false, "", "", err
	}
	if n != 65 {
		return false, "", "", errors.New("signature must be 65 bytes long")
	}
	header, r, s := splitSignature(dSig[:n])
	if header < 27 || header > 46 {
		return false, "", "", errors.New("header byte out of range")
	}
	if r.Cmp(secp256k1.NCurve) >= 0 || r.Cmp(zero) == 0 {
		return false, "", "", errors.New("r-value out of range")
	}
	if s.Cmp(secp256k1.NCurve) >= 0 || s.Cmp(zero) == 0 {
		return false, "", "", errors.New("s-value out of range")
	}
	uncompressed := false
	addrType := "p2pkh"
	if header >= 43 {
		header -= 16
		addrType = ""
	} else if header >= 39 {
		header -= 12
		addrType = "p2wpkh"
	} else if header >= 35 {
		header -= 8
		addrType = "p2wpkh-p2sh"
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
	mBytes := msgMagic(message)
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
				panic(err)
			}
			if addr == address {
				return true, hex.EncodeToString(pubKey), fmt.Sprintf("message verified to be from %s", address), nil
			}
		}
		return false, hex.EncodeToString(pubKey), fmt.Sprintln("message failed to verify"), nil
	}
	if addrType == "" {
		return false, "", "", errors.New("unknown address type")
	}
	addr, _, err := deriveAddress(pubKey, addrType)
	if err != nil {
		panic(err)
	}
	if addr == address {
		return true, hex.EncodeToString(pubKey), fmt.Sprintf("message verified to be from %s", address), nil
	}
	return false, hex.EncodeToString(pubKey), fmt.Sprintln("message failed to verify"), nil
}

func main() {

	key := big.NewInt(1000)
	start := time.Now()
	raw, _ := createRawPubKey(key)
	pk := createPubKey(raw, false)
	fmt.Println(createAddress(pk))
	fmt.Println(createNestedSegwit(pk))
	fmt.Println(hex.EncodeToString([]byte{5, 00, 20}))
	addr, _ := createNativeSegwit(pk)
	fmt.Println(addr)
	fmt.Printf("uint64: %v\n", uint64(18446744073709551615))

	fmt.Println(hex.EncodeToString(varInt(12356333474345788523)))
	fmt.Println(hex.EncodeToString(msgMagic("语言处理")))
	a := secp256k1.GenPoint
	b := identityPoint
	fmt.Println(!a.Eq(b))
	fmt.Printf("%p%p\n", a.X, &secp256k1.GenPoint.X)

	fmt.Println(deriveAddress(pk, "p2wpkh"))
	fmt.Printf("%p\n", secp256k1.GenPoint.X)
	fmt.Println(secp256k1.GenPoint)
	fmt.Printf("%p\n", secp256k1.GenPoint.X)
	fmt.Println(secp256k1.GenPoint)
	var pr JacobianPoint
	fmt.Println(pr.Mul(key, pr.Mul(key, secp256k1.GenPoint)))
	fmt.Println(secp256k1.GenPoint)
	fmt.Println(time.Since(start))
	th := big.NewInt(1000)
	fmt.Println(sign(th, th))
	th2 := big.NewInt(10000)
	fmt.Println(sign(th2, th2))
	fmt.Println(sign(th2, th2))

	fmt.Println(VerifyMessage("175A5YsPUdM71mnNCC3i8faxxYJgBonjWL", "ECDSA is the most fun I have ever experienced", "HyiLDcQQ1p2bKmyqM0e5oIBQtKSZds4kJQ+VbZWpr0kYA6Qkam2MlUeTr+lm1teUGHuLapfa43JjyrRqdSA0pxs=", true))

}
