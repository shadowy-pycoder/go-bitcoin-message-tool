package bmt

import (
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// testTempFile creates a temporary file for testing purposes.
//
// Parameters:
//   - b: a pointer to a testing.B object, used to run the benchmark.
//
// Return:
//   - string: the name of the temporary file.
//   - func(): a function that removes the temporary file.
func testTempFile(b *testing.B) (string, func()) {
	b.Helper()

	tf, err := os.CreateTemp("", "test.txt")
	if err != nil {
		b.Fatal(err)
	}
	tf.Close()
	return tf.Name(), func() { os.Remove(tf.Name()) }
}

// NewInt converts a hexadecimal string to a big.Int pointer.
//
// Parameters:
//   - s: a string representing a hexadecimal number.
//
// Returns:
//   - *big.Int: a pointer to a big.Int representing the converted number.
func NewInt(s string) *big.Int {
	num, err := new(big.Int).SetString(s, 16)
	if !err {
		os.Exit(1)
	}
	return num
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

// BenchmarkCreateWallets is a benchmark function that measures the performance of the CreateWallets function.
//
// Parameters:
//   - b: a pointer to a testing.B object, used to run the benchmark.
//
// Return:
//   - None.
func BenchmarkCreateWallets(b *testing.B) {
	tf, tfclose := testTempFile(b)
	defer tfclose()
	CreateWallets(b.N, tf)
}

// TestCreateNewWalletFromRawPrivateKey is a unit test function that tests the
// CreateNewWallet function with raw private keys. It verifies that the function
// correctly creates a new wallet with the expected values.
//
// Parameters:
//   - t: a pointer to a testing.T object, used for testing.
//
// Return:
//   - None.
func TestCreateNewWalletFromRawPrivateKey(t *testing.T) {
	var testcases = []struct {
		name     string
		privKey  *big.Int
		expected *Wallet
	}{
		{
			name:    "create wallet from provided private key in raw format",
			privKey: NewInt("c25c21007c61110c6a2162f30aacb5e94c2a304d9104809814266067da2d78aa"),
			expected: &Wallet{
				PrivKey: &PrivateKey{Raw: NewInt("c25c21007c61110c6a2162f30aacb5e94c2a304d9104809814266067da2d78aa"),
					Wif:          NewStr("L3jXBC4CuXiLmjiBxziRmj1mRFm5Fhg1XM5SV6BBnuJvB686Dwxo"),
					Uncompressed: false,
				},
				RawPubKey: &Point{
					X: NewInt("e4ab48ce61667f57bb9ca0f31b9bca94981303004d3802b1c11faa9343a820ba"),
					Y: NewInt("17d5acd0ade3141bdccab4689a82151e638a70a56c1b4d38788e77c76e414dd3"),
				},
				PubKey: "03e4ab48ce61667f57bb9ca0f31b9bca94981303004d3802b1c11faa9343a820ba",
				Legacy: "1LBdJkrB4nkWkLLdKSBAD2CPRrpSaYQW51",
				Nested: "39RBCbgESnqjHpapfvqVPfLCPGrvGKxpbC",
				Native: "bc1q6fkdkwv5p6mxdhyj2gxhgu2tp5np53g6g8u0t0",
			},
		},
		{
			name:    "create wallet again from provided private key in raw format",
			privKey: NewInt("af891cd2de010ece231f843fe2aebe49fdc4481473954fbe6d5f46a0a839b61e"),
			expected: &Wallet{
				PrivKey: &PrivateKey{Raw: NewInt("af891cd2de010ece231f843fe2aebe49fdc4481473954fbe6d5f46a0a839b61e"),
					Wif:          NewStr("L36vqtR9oaBBmCJdbtoqyVQQ8UA34YpyBqRRjT9rJSPWMg1Vomzr"),
					Uncompressed: false,
				},
				RawPubKey: &Point{
					X: NewInt("e483d1df60d0c9e16035672dfb92d7ddac6858b5233d33bb04996ae6a23f0149"),
					Y: NewInt("d0fb3cafc082957fdd8934a9fa2b5fbf2fee701ca595da7bb79a95f0063a13c5"),
				},
				PubKey: "03e483d1df60d0c9e16035672dfb92d7ddac6858b5233d33bb04996ae6a23f0149",
				Legacy: "13KXYTfq5FRQj6T3t6ds6FYqCDymYMwdmC",
				Nested: "34GeUW8iPUkWdfQSWFvumAt5RGtxhp3KCG",
				Native: "bc1qr9cncqd8v5j9uv86pfprqlkuh7htp5uwu6x56m",
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual, err := CreateNewWallet(testcase.privKey, nil)
			require.NoError(t, err)
			require.Equal(t, actual, testcase.expected)
		})
	}
}

// TestCreateNewWalletFromRawPrivateKey is a unit test function that tests the
// CreateNewWallet function with private keys in Wallet Import Format (WIF). It verifies that the function
// correctly creates a new wallet with the expected values.
//
// Parameters:
//   - t: a pointer to a testing.T object, used for testing.
//
// Return:
//   - None.
func TestCreateNewWalletFromWifPrivateKey(t *testing.T) {
	var testcases = []struct {
		name     string
		privKey  *string
		expected *Wallet
	}{
		{
			name:    "create wallet from WIF compressed private key",
			privKey: NewStr("KyjEvvcF74ri9zZitiwj1yPbo9ZL7sRjaiXvZzMzyaFMRQmEEnVD"),
			expected: &Wallet{
				PrivKey: &PrivateKey{Raw: NewInt("4addbf0fce208919c5144b8c46ca4c6dc57dfa35aada13a73c21edc2459f6d3f"),
					Wif:          NewStr("KyjEvvcF74ri9zZitiwj1yPbo9ZL7sRjaiXvZzMzyaFMRQmEEnVD"),
					Uncompressed: false,
				},
				RawPubKey: &Point{
					X: NewInt("66fde8efb47bfe53be63cccd068996f3a1c9172f1c2f6bc345dff6c589daefc5"),
					Y: NewInt("379ab4aa30d3247cb6b7c327067bd8199ff7bec32205ef043d3c9239ec6765b7"),
				},
				PubKey: "0366fde8efb47bfe53be63cccd068996f3a1c9172f1c2f6bc345dff6c589daefc5",
				Legacy: "14VXJudstcvqpx56BPQFSYJ1K39KGc3twM",
				Nested: "32vwEU1Esvp1AywrYgrnziHCaigLTn5AKN",
				Native: "bc1qyex4xghj4rldkysse2hdpt0arphh78xhp28ze2",
			},
		},
		{
			name:    "create wallet from WIF uncompressed private key",
			privKey: NewStr("5J6cvNuJ5DzrceH4EDhAhYbNzosJr1CVJ6J22Wsh6WDFjYJZFiS"),
			expected: &Wallet{
				PrivKey: &PrivateKey{Raw: NewInt("25164ab11c348f5a732d4627c0504d863110d2f4703b031168aecb0c0913377b"),
					Wif:          NewStr("5J6cvNuJ5DzrceH4EDhAhYbNzosJr1CVJ6J22Wsh6WDFjYJZFiS"),
					Uncompressed: true,
				},
				RawPubKey: &Point{
					X: NewInt("38ec538fde2fc2b441658906a448d03306d6c0ba426339f563a1aa066400267e"),
					Y: NewInt("6589da31927ce03e0548711a3639f50628e2520985c9e9a6b05176b5d26f93d5"),
				},
				PubKey: "0438ec538fde2fc2b441658906a448d03306d6c0ba426339f563a1aa066400267e6589da31927ce03e0548711a3639f50628e2520985c9e9a6b05176b5d26f93d5",
				Legacy: "13tkrNcktzB8CS2N5gg1r1gqA8a3Z42fTG",
				Nested: "",
				Native: "",
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual, err := CreateNewWallet(nil, testcase.privKey)
			require.NoError(t, err)
			require.Equal(t, actual, testcase.expected)
		})
	}
}

// TestCreateNewWalletErr tests the CreateNewWallet function for error cases.
//
// It tests different scenarios where the function should return an error message.
func TestCreateNewWalletErr(t *testing.T) {
	var testcases = []struct {
		name       string
		privKeyRaw *big.Int
		privKeyWif *string
		errMsg     string
	}{
		{
			name:       "cannot specify both raw and wif private keys",
			privKeyRaw: NewInt("3a6039a639aca056ebd7cf4613a6aa6933a135f4b8e38e413d093814fdc6c1e6"),
			privKeyWif: NewStr("KyBBjqHmb5yXS8ZCPjV3J9by9qP8XuZbZMAhRLchfyMVDh24xA6v"),
			errMsg:     "cannot specify both raw and wif",
		},
		{
			name:       "provided private key is out of range",
			privKeyRaw: new(big.Int).Add(Secp256k1.NCurve, one),
			privKeyWif: nil,
			errMsg:     "scalar is out of range",
		},
		{
			name:       "invalid WIF string provided",
			privKeyRaw: nil,
			privKeyWif: NewStr("test"),
			errMsg:     "failed decoding wif string",
		},
		{
			name:       "provided WIF string has invalid checksum",
			privKeyRaw: nil,
			privKeyWif: NewStr("KyBBjqHmb5yXS8ZCPjV3J9by9qP8XuZbZMAhRLchfyMVDh24xA6"),
			errMsg:     "invalid wif checksum",
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := CreateNewWallet(testcase.privKeyRaw, testcase.privKeyWif)
			require.EqualError(t, err, testcase.errMsg)
		})
	}
}

// TestCreateNewWalletRandom tests the CreateNewWallet function with random inputs.
//
// It ensures that the generated wallets have no errors and that the WIF of the wallets match.
func TestCreateNewWalletRandom(t *testing.T) {
	wallet, err := CreateNewWallet(nil, nil)
	require.NoError(t, err)
	w, err := CreateNewWallet(wallet.PrivKey.Raw, nil)
	require.NoError(t, err)
	require.Equal(t, wallet.PrivKey.Wif, w.PrivKey.Wif)
}

// TestAddPoints tests the point addition in Jacobian coordinates.
func TestAddPoints(t *testing.T) {
	var pt JacobianPoint

	var testcases = []struct {
		name     string
		pointOne *JacobianPoint
		pointTwo *JacobianPoint
		expected *Point
	}{
		{
			name:     "add two generator points",
			pointOne: Secp256k1.GenPoint,
			pointTwo: Secp256k1.GenPoint,
			expected: &Point{
				X: NewInt("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
				Y: NewInt("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			},
		},
		{
			name:     "add generator point to a random point",
			pointOne: Secp256k1.GenPoint,
			pointTwo: NewJacobianPoint(NewInt("599499143ab0bb1459478e96d1c72420098fc50a69bf23fc897e76bc64510a30"),
				NewInt("ebcd34bffa9daa4009c2dcb94a4f0a283ca2bc58cfd99c95b588118b74f661e9"), one),
			expected: &Point{
				X: NewInt("802b138ed913ccf1daad29d8b77265f2b2ab519f696036337d3610061047fbe0"),
				Y: NewInt("3741c360f64b998639511b52860dc115dd605267ab80c2163ef165fe5f574e60"),
			},
		},
		{
			name:     "add two points where one of which is point at infinity",
			pointOne: IdentityPoint,
			pointTwo: NewJacobianPoint(NewInt("599499143ab0bb1459478e96d1c72420098fc50a69bf23fc897e76bc64510a30"),
				NewInt("ebcd34bffa9daa4009c2dcb94a4f0a283ca2bc58cfd99c95b588118b74f661e9"), one),
			expected: &Point{
				X: NewInt("599499143ab0bb1459478e96d1c72420098fc50a69bf23fc897e76bc64510a30"),
				Y: NewInt("ebcd34bffa9daa4009c2dcb94a4f0a283ca2bc58cfd99c95b588118b74f661e9"),
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual := pt.Add(testcase.pointOne, testcase.pointTwo).ToAffine()
			equal := testcase.expected.Eq(actual)
			require.True(t, equal)
		})
	}
}

// TestDblPoint is a test function to verify the point doubling operation in elliptic curve cryptography.
//
// It tests different scenarios including doubling a generator point, a random point, and a point at infinity.
// The function compares the expected result with the actual result after performing the point doubling operation.
func TestDblPoint(t *testing.T) {
	var pt JacobianPoint

	var testcases = []struct {
		name     string
		point    *JacobianPoint
		expected *Point
	}{
		{
			name:  "double a generator point",
			point: Secp256k1.GenPoint,
			expected: &Point{
				X: NewInt("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
				Y: NewInt("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			},
		},
		{
			name: "double a random point",
			point: NewJacobianPoint(NewInt("fb9650ee5895fc2f13cc954a805622c1e058e55a768d500b8657351f7d4b310e"),
				NewInt("bce77ab81fb226ac1471e6fbf6cd326d4463e4c00afc58e53c9dfaf3e91493ab"), one),
			expected: &Point{
				X: NewInt("e12283534976811ef1a35cdf0495b40fcc25fb508161b55d16812e32a0e8c4b"),
				Y: NewInt("92dc549da5982e00a3eb3156e1c6b9a79eabf0bd1c1b334c9451f7ea6347ac87"),
			},
		},
		{
			name:  "double point at infinity",
			point: IdentityPoint,
			expected: &Point{
				X: Secp256k1.PCurve,
				Y: new(big.Int).Set(zero),
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual := pt.Dbl(testcase.point).ToAffine()
			equal := testcase.expected.Eq(actual)
			require.True(t, equal)
		})
	}
}

// TestMulPoint tests point multiplication.
func TestMulPoint(t *testing.T) {
	var pt JacobianPoint

	var testcases = []struct {
		name     string
		point    *JacobianPoint
		number   *big.Int
		expected *Point
	}{
		{
			name:   "multiply a generator point by number",
			point:  Secp256k1.GenPoint,
			number: NewInt("51c4dba2c28fc89b208550477a514c87f9d0db0354f03b7c61f08c0a0e3118a2"),
			expected: &Point{
				X: NewInt("bb6c1de01f36618ae05f7c183c22dfa8797e779f39537752c27e2dc045b0e694"),
				Y: NewInt("2f8af53270bf045f2258834b6dad7481ad6fca009d80f5b54697b08d104fc7b3"),
			},
		},
		{
			name: "multiply a random point by number",
			point: NewJacobianPoint(NewInt("1fe4e60da1652de650a3b173f835a438bc94de16e4ab497eca2e899c767eaf2c"),
				NewInt("dd6c126f037d77a48109e64bacdce7d37bcdd1540319d7063a20a546a321937d"), one),
			number: NewInt("51c4dba2c28fc89b208550477a514c87f9d0db0354f03b7c61f08c0a0e3118a2"),
			expected: &Point{
				X: NewInt("9b4c6c9014ccd964d33c320610f219c1034d5f26d64e49c307ec3890ca33b770"),
				Y: NewInt("b0ba7b592b01f13805d2935eac63474d0d83fa29e7d8700f740d6a019135accf"),
			},
		},
		{
			name:     "multiply generator point by N",
			point:    Secp256k1.GenPoint,
			number:   Secp256k1.NCurve,
			expected: IdentityPoint.ToAffine(),
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual := pt.Mul(testcase.number, testcase.point).ToAffine()
			equal := testcase.expected.Eq(actual)
			require.True(t, equal)
		})
	}
}
