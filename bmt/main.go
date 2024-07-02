package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/golangcrypto/ripemd160"
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
	Y: big.NewInt(0),
	Z: big.NewInt(1),
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

func main() {
	fmt.Println(ecDbl(secp256k1.GenPoint))
	fmt.Println(ecDbl(identityPoint))
}
