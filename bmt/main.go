package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

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
)

type JacobianPoint struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
}

type Point struct {
	X *big.Int
	Y *big.Int
}

type Secp256k1 struct {
	PCurve   *big.Int
	NCurve   *big.Int
	ACurve   *big.Int
	BCurve   *big.Int
	GenPoint *JacobianPoint
}

var secp256k1 = Secp256k1{
	PCurve: pCurve,
	NCurve: nCurve,
	ACurve: aCurve,
	BCurve: bCurve,
	GenPoint: &JacobianPoint{
		X: genPointX,
		Y: genPointY,
		Z: one,
	},
}

var identityPoint = &JacobianPoint{
	X: pCurve,
	Y: zero,
	Z: one,
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
// b - input byte slice to be hashed.
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
// b - input byte slice to be hashed.
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

// ToAffine converts a point from Jacobian coordinates to affine coordinates.
//
// Parameter:
// p - the point in Jacobian coordinates.
// Returns:
// A pointer to a Point representing the point in affine coordinates.
func ToAffine(p *JacobianPoint) *Point {
	var x, y big.Int
	invZ := ModInverse(p.Z, secp256k1.PCurve)
	invZ2 := new(big.Int).Exp(invZ, two, nil)
	x.Mul(p.X, invZ2).Mod(&x, secp256k1.PCurve)
	y.Mul(p.Y, invZ2).Mul(&y, invZ).Mod(&y, secp256k1.PCurve)
	return &Point{X: &x, Y: &y}
}

// ToJacobian converts a point from affine coordinates to Jacobian coordinates.
//
// Parameter:
// p - a pointer to a Point representing the point in affine coordinates.
// Returns:
// A pointer to a JacobianPoint representing the point in Jacobian coordinates.
func ToJacobian(p *Point) *JacobianPoint {
	return &JacobianPoint{X: p.X, Y: p.Y, Z: one}
}

// ValidKey checks if the given big.Int scalar is a valid key.
//
// Parameters:
// - scalar: a pointer to a big.Int representing the scalar value.
//
// Returns:
// - bool: true if the scalar is valid, false otherwise.
func ValidKey(scalar *big.Int) bool {
	return scalar.Cmp(zero) == 1 && scalar.Cmp(secp256k1.NCurve) == -1
}

// ValidPoint checks if a given point is on the elliptic curve.
//
// Parameters:
// - p: a pointer to a Point representing the point to be validated.
//
// Returns:
// - bool: true if the point is valid, false otherwise.
func ValidPoint(p *Point) bool {
	var r1, r2 big.Int
	r1.Exp(p.X, three, nil).Add(&r1, secp256k1.BCurve).Mod(&r1, secp256k1.PCurve)
	r2.Exp(p.Y, two, secp256k1.PCurve)
	return r1.Cmp(&r2) == 0
}

// ecDbl performs a point doubling operation in the elliptic curve cryptography with 256 Bit Primes.
//
// Parameter:
// p - a pointer to a JacobianPoint struct representing the point to be doubled.
// Returns:
// A pointer to a JacobianPoint struct representing the result of the point doubling operation.
//
// Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes
// Shay Gueron, Vlad Krasnov
// https://eprint.iacr.org/2013/816.pdf page 4
func ecDbl(p *JacobianPoint) *JacobianPoint {
	var Y2, S, M, x, y, z, tx, ty big.Int
	if p.X.Cmp(secp256k1.PCurve) == 0 {
		return p
	}
	Y2.Mul(p.Y, p.Y)
	S.Mul(four, p.X).Mul(&S, &Y2).Mod(&S, secp256k1.PCurve)
	M.Mul(three, p.X).Mul(&M, p.X)
	x.Mul(&M, &M).Sub(&x, tx.Mul(two, &S)).Mod(&x, secp256k1.PCurve)
	y.Mul(&M, ty.Sub(&S, &x)).Sub(&y, ty.Mul(&Y2, &Y2).Mul(&ty, eight)).Mod(&y, secp256k1.PCurve)
	z.Mul(two, p.Y).Mul(&z, p.Z).Mod(&z, secp256k1.PCurve)
	return &JacobianPoint{X: &x, Y: &y, Z: &z}

}

func getPrecomputes() []*JacobianPoint {
	precomputes := make([]*JacobianPoint, 256)
	dbl := secp256k1.GenPoint
	for i := range 256 {
		precomputes[i] = dbl
		dbl = ecDbl(dbl)
	}
	return precomputes
}

// ecAdd performs elliptic curve point addition in Jacobian coordinates for the secp256k1 curve.
//
// It takes two JacobianPoint points p and q as input parameters and returns a JacobianPoint point.
//
// Parameters:
// - p: a pointer to a JacobianPoint representing the first point.
// - q: a pointer to a JacobianPoint representing the second point.
//
// Returns:
// - a pointer to a JacobianPoint representing the sum of p and q.
//
// Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes
// Shay Gueron, Vlad Krasnov
// https://eprint.iacr.org/2013/816.pdf page 4
func ecAdd(p, q *JacobianPoint) *JacobianPoint {
	var PZ2, QZ2, U1, U2, S1, S2, H, R, H2, H3, x, tx, y, ty, z big.Int
	if p.X.Cmp(secp256k1.PCurve) == 0 {
		return q
	}
	if q.X.Cmp(secp256k1.PCurve) == 0 {
		return p
	}
	PZ2.Mul(p.Z, p.Z)
	QZ2.Mul(q.Z, q.Z)
	U1.Mul(p.X, &QZ2).Mod(&U1, secp256k1.PCurve)
	U2.Mul(q.X, &PZ2).Mod(&U2, secp256k1.PCurve)
	S1.Mul(p.Y, &QZ2).Mul(&S1, q.Z).Mod(&S1, secp256k1.PCurve)
	S2.Mul(q.Y, &PZ2).Mul(&S2, p.Z).Mod(&S2, secp256k1.PCurve)

	if U1.Cmp(&U2) == 0 {
		if S1.Cmp(&S2) == 0 {
			return ecDbl(p)
		} else {
			return identityPoint
		}

	}
	H.Sub(&U2, &U1).Mod(&H, secp256k1.PCurve)
	R.Sub(&S2, &S1).Mod(&R, secp256k1.PCurve)
	H2.Mul(&H, &H).Mod(&H2, secp256k1.PCurve)
	H3.Mul(&H2, &H).Mod(&H3, secp256k1.PCurve)
	x.Mul(&R, &R).Sub(&x, &H3).Sub(&x, tx.Mul(two, &U1).Mul(&tx, &H2)).Mod(&x, secp256k1.PCurve)
	y.Mul(&R, y.Mul(&U1, &H2).Sub(&y, &x)).Sub(&y, ty.Mul(&S1, &H3)).Mod(&y, secp256k1.PCurve)
	z.Mul(&H, p.Z).Mul(&z, q.Z).Mod(&z, secp256k1.PCurve)
	return &JacobianPoint{X: &x, Y: &y, Z: &z}

}

// ecMul performs elliptic curve multiplication.
//
// It takes two parameters:
// - scalar: a pointer to a big.Int representing the scalar value.
// - point: a pointer to a JacobianPoint representing the base point.
//
// It returns a pointer to a JacobianPoint representing the result of the multiplication.
//
// https://paulmillr.com/posts/noble-secp256k1-fast-ecc/#fighting-timing-attacks
func ecMul(scalar *big.Int, point *JacobianPoint) *JacobianPoint {
	var n, fakeN, x, y, z big.Int
	n.Set(scalar)
	p := &JacobianPoint{
		X: pCurve,
		Y: zero,
		Z: one,
	}
	if point == nil {
		fakeP := &JacobianPoint{
			X: pCurve,
			Y: zero,
			Z: one,
		}
		fakeN.Xor(pow256M1, &n)
		for _, q := range precomputes {
			if IsOdd(&n) {
				p = ecAdd(p, q)
			} else {
				fakeP = ecAdd(fakeP, q)
			}
			n.Rsh(&n, 1)
			fakeN.Rsh(&fakeN, 1)

		}
	} else {
		q := &JacobianPoint{
			X: x.Set(point.X),
			Y: y.Set(point.Y),
			Z: z.Set(point.Z),
		}
		for n.Cmp(zero) == 1 {
			if IsOdd(&n) {
				p = ecAdd(p, q)
			}
			n.Rsh(&n, 1)
			q = ecDbl(q)
		}
	}
	return &JacobianPoint{X: p.X, Y: p.Y, Z: p.Z}
}

// joinBytes concatenates the byte slices in s into a single byte slice.
//
// s - variadic parameter containing byte slices to be concatenated.
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
// - privKey: a pointer to a big.Int representing the private key.
// - safe: a boolean indicating whether to use a safe method for generating the public key.
//
// Returns:
// - a pointer to a Point representing the raw public key.
// - an error if the generated point is not on the curve.
func createRawPubKey(privKey *big.Int, safe bool) (*Point, error) {
	var rawPubKey *Point
	if !safe {
		rawPubKey = ToAffine(ecMul(privKey, secp256k1.GenPoint))
	} else {
		rawPubKey = ToAffine(ecMul(privKey, nil))
	}
	if !ValidPoint(rawPubKey) {
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
// - a byte slice representing the public key in the specified format.
func createPubKey(rawPubKey *Point, uncompressed bool) []byte {
	var prefix uint8
	if uncompressed {
		return bytes.Join([][]byte{{4}, rawPubKey.X.Bytes(), rawPubKey.Y.Bytes()}, []byte(""))
	}
	if IsOdd(rawPubKey.Y) {
		prefix = 3
	} else {
		prefix = 2
	}
	return joinBytes([][]byte{{prefix}, rawPubKey.X.Bytes()}...)
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
// - pubKey: a byte slice representing the public key.
//
// Returns:
// - a string representing the Bitcoin address.
func createAddress(pubKey []byte) string {
	address := joinBytes([][]byte{{0}, Ripemd160SHA256(pubKey)}...)
	return base58.Encode(joinBytes([][]byte{address, checkSum(address)}...))
}

func main() {

	key := big.NewInt(1000)
	start := time.Now()
	raw, _ := createRawPubKey(key, false)
	pk := createPubKey(raw, true)
	fmt.Println(createAddress(pk))
	fmt.Println(time.Since(start))

}
