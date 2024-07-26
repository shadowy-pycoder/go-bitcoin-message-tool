package bmt

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	Message      = "ECDSA is the most fun I have ever experienced"
	FancyMessage = `乇匚ᗪ丂卂 丨丂 ㄒ卄乇 爪ㄖ丂ㄒ 千ㄩ几 丨 卄卂ᐯ乇 乇ᐯ乇尺 乇乂卩乇尺丨乇几匚乇ᗪ

😒🥷🐲👩‍🎓   🧑‍💻   🤴   😖   👬   💔   😸   🥱   🤐   ✍   💂‍♂️   🚣‍♀️  

👧🧒👦👩🧑👨👩‍🦱🧑‍🦱

👨‍🦱👩‍🦰🧑‍🦰👨‍🦰👱‍♀️👱👱‍♂️ ☕  ȹȐšԨԢш҂܇ŸΆঈѣֆцѵऀĳݩΙ̩Ɇ`
)

func ToBytes(s string) *[]byte {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return &bs
}

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
	t.Parallel()

	var testcases = []struct {
		name     string
		privKey  *[]byte
		expected *wallet
	}{
		{
			name:    "create wallet from provided private key in raw format",
			privKey: ToBytes("c25c21007c61110c6a2162f30aacb5e94c2a304d9104809814266067da2d78aa"),
			expected: &wallet{
				privKey: &privatekey{raw: NewModNScalar("c25c21007c61110c6a2162f30aacb5e94c2a304d9104809814266067da2d78aa"),
					wif:          NewStr("L3jXBC4CuXiLmjiBxziRmj1mRFm5Fhg1XM5SV6BBnuJvB686Dwxo"),
					uncompressed: false,
				},
				rawPubKey: &Point{
					X: *NewFieldVal("e4ab48ce61667f57bb9ca0f31b9bca94981303004d3802b1c11faa9343a820ba"),
					Y: *NewFieldVal("17d5acd0ade3141bdccab4689a82151e638a70a56c1b4d38788e77c76e414dd3"),
				},
				pubKey:  "03e4ab48ce61667f57bb9ca0f31b9bca94981303004d3802b1c11faa9343a820ba",
				legacy:  "1LBdJkrB4nkWkLLdKSBAD2CPRrpSaYQW51",
				nested:  "39RBCbgESnqjHpapfvqVPfLCPGrvGKxpbC",
				native:  "bc1q6fkdkwv5p6mxdhyj2gxhgu2tp5np53g6g8u0t0",
				taproot: "bc1puzp40apyn38h3nqhzzxk6tmxxwvd0jcegnk4k88qvxntstsfhyvq5nr3us",
			},
		},
		{
			name:    "create wallet again from provided private key in raw format",
			privKey: ToBytes("af891cd2de010ece231f843fe2aebe49fdc4481473954fbe6d5f46a0a839b61e"),
			expected: &wallet{
				privKey: &privatekey{raw: NewModNScalar("af891cd2de010ece231f843fe2aebe49fdc4481473954fbe6d5f46a0a839b61e"),
					wif:          NewStr("L36vqtR9oaBBmCJdbtoqyVQQ8UA34YpyBqRRjT9rJSPWMg1Vomzr"),
					uncompressed: false,
				},
				rawPubKey: &Point{
					X: *NewFieldVal("e483d1df60d0c9e16035672dfb92d7ddac6858b5233d33bb04996ae6a23f0149"),
					Y: *NewFieldVal("d0fb3cafc082957fdd8934a9fa2b5fbf2fee701ca595da7bb79a95f0063a13c5"),
				},
				pubKey:  "03e483d1df60d0c9e16035672dfb92d7ddac6858b5233d33bb04996ae6a23f0149",
				legacy:  "13KXYTfq5FRQj6T3t6ds6FYqCDymYMwdmC",
				nested:  "34GeUW8iPUkWdfQSWFvumAt5RGtxhp3KCG",
				native:  "bc1qr9cncqd8v5j9uv86pfprqlkuh7htp5uwu6x56m",
				taproot: "bc1ph4zg3xz7z0kvmdp9nne6kpyc8yk9rsweepa3g5se40zkqa7rvwvslkl8fd",
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
	t.Parallel()

	var testcases = []struct {
		name     string
		privKey  *string
		expected *wallet
	}{
		{
			name:    "create wallet from WIF compressed private key",
			privKey: NewStr("KyjEvvcF74ri9zZitiwj1yPbo9ZL7sRjaiXvZzMzyaFMRQmEEnVD"),
			expected: &wallet{
				privKey: &privatekey{raw: NewModNScalar("4addbf0fce208919c5144b8c46ca4c6dc57dfa35aada13a73c21edc2459f6d3f"),
					wif:          NewStr("KyjEvvcF74ri9zZitiwj1yPbo9ZL7sRjaiXvZzMzyaFMRQmEEnVD"),
					uncompressed: false,
				},
				rawPubKey: &Point{
					X: *NewFieldVal("66fde8efb47bfe53be63cccd068996f3a1c9172f1c2f6bc345dff6c589daefc5"),
					Y: *NewFieldVal("379ab4aa30d3247cb6b7c327067bd8199ff7bec32205ef043d3c9239ec6765b7"),
				},
				pubKey:  "0366fde8efb47bfe53be63cccd068996f3a1c9172f1c2f6bc345dff6c589daefc5",
				legacy:  "14VXJudstcvqpx56BPQFSYJ1K39KGc3twM",
				nested:  "32vwEU1Esvp1AywrYgrnziHCaigLTn5AKN",
				native:  "bc1qyex4xghj4rldkysse2hdpt0arphh78xhp28ze2",
				taproot: "bc1pss2mar9sv2nktnx8ujqrjd9ld7n0zn9swl7zup5pcl8shq9es4kqlgx6g3",
			},
		},
		{
			name:    "create wallet from WIF uncompressed private key",
			privKey: NewStr("5J6cvNuJ5DzrceH4EDhAhYbNzosJr1CVJ6J22Wsh6WDFjYJZFiS"),
			expected: &wallet{
				privKey: &privatekey{raw: NewModNScalar("25164ab11c348f5a732d4627c0504d863110d2f4703b031168aecb0c0913377b"),
					wif:          NewStr("5J6cvNuJ5DzrceH4EDhAhYbNzosJr1CVJ6J22Wsh6WDFjYJZFiS"),
					uncompressed: true,
				},
				rawPubKey: &Point{
					X: *NewFieldVal("38ec538fde2fc2b441658906a448d03306d6c0ba426339f563a1aa066400267e"),
					Y: *NewFieldVal("6589da31927ce03e0548711a3639f50628e2520985c9e9a6b05176b5d26f93d5"),
				},
				pubKey:  "0438ec538fde2fc2b441658906a448d03306d6c0ba426339f563a1aa066400267e6589da31927ce03e0548711a3639f50628e2520985c9e9a6b05176b5d26f93d5",
				legacy:  "13tkrNcktzB8CS2N5gg1r1gqA8a3Z42fTG",
				nested:  "",
				native:  "",
				taproot: "",
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

//TestCreateNewWalletErr tests the CreateNewWallet function for error cases.

// It tests different scenarios where the function should return an error message.
func TestCreateNewWalletErr(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name       string
		privKeyRaw *[]byte
		privKeyWif *string
		errMsg     string
	}{
		{
			name:       "cannot specify both raw and wif private keys",
			privKeyRaw: ToBytes("3a6039a639aca056ebd7cf4613a6aa6933a135f4b8e38e413d093814fdc6c1e6"),
			privKeyWif: NewStr("KyBBjqHmb5yXS8ZCPjV3J9by9qP8XuZbZMAhRLchfyMVDh24xA6v"),
			errMsg:     "cannot specify both raw and wif",
		},
		{
			name:       "provided private key is out of range",
			privKeyRaw: ToBytes("00"),
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
	pk := wallet.privKey.raw.Bytes()
	pkBytes := pk[:]
	w, err := CreateNewWallet(&pkBytes, nil)
	require.NoError(t, err)
	require.Equal(t, wallet.privKey.wif, w.privKey.wif)
}

// TestAddPoints tests the point addition in Jacobian coordinates.
func TestAddPoints(t *testing.T) {
	t.Parallel()

	var pt JacobianPoint

	var testcases = []struct {
		name     string
		pointOne *JacobianPoint
		pointTwo *JacobianPoint
		expected *Point
	}{
		{
			name:     "add two generator points",
			pointOne: GenPoint,
			pointTwo: GenPoint,
			expected: &Point{
				X: *NewFieldVal("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
				Y: *NewFieldVal("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			},
		},
		{
			name:     "add generator point to a random point",
			pointOne: GenPoint,
			pointTwo: NewJacobianPoint(NewFieldVal("599499143ab0bb1459478e96d1c72420098fc50a69bf23fc897e76bc64510a30"),
				NewFieldVal("ebcd34bffa9daa4009c2dcb94a4f0a283ca2bc58cfd99c95b588118b74f661e9"), one),
			expected: &Point{
				X: *NewFieldVal("802b138ed913ccf1daad29d8b77265f2b2ab519f696036337d3610061047fbe0"),
				Y: *NewFieldVal("3741c360f64b998639511b52860dc115dd605267ab80c2163ef165fe5f574e60"),
			},
		},
		{
			name:     "add two points where one of which is point at infinity",
			pointOne: IdentityPoint,
			pointTwo: NewJacobianPoint(NewFieldVal("599499143ab0bb1459478e96d1c72420098fc50a69bf23fc897e76bc64510a30"),
				NewFieldVal("ebcd34bffa9daa4009c2dcb94a4f0a283ca2bc58cfd99c95b588118b74f661e9"), one),
			expected: &Point{
				X: *NewFieldVal("599499143ab0bb1459478e96d1c72420098fc50a69bf23fc897e76bc64510a30"),
				Y: *NewFieldVal("ebcd34bffa9daa4009c2dcb94a4f0a283ca2bc58cfd99c95b588118b74f661e9"),
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
	t.Parallel()

	var pt JacobianPoint

	var testcases = []struct {
		name     string
		point    *JacobianPoint
		expected *Point
	}{
		{
			name:  "double a generator point",
			point: GenPoint,
			expected: &Point{
				X: *NewFieldVal("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
				Y: *NewFieldVal("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			},
		},
		{
			name: "double a random point",
			point: NewJacobianPoint(NewFieldVal("fb9650ee5895fc2f13cc954a805622c1e058e55a768d500b8657351f7d4b310e"),
				NewFieldVal("bce77ab81fb226ac1471e6fbf6cd326d4463e4c00afc58e53c9dfaf3e91493ab"), one),
			expected: &Point{
				X: *NewFieldVal("0e12283534976811ef1a35cdf0495b40fcc25fb508161b55d16812e32a0e8c4b"),
				Y: *NewFieldVal("92dc549da5982e00a3eb3156e1c6b9a79eabf0bd1c1b334c9451f7ea6347ac87"),
			},
		},
		{
			name:  "double point at infinity",
			point: IdentityPoint,
			expected: &Point{
				X: IdentityPoint.X,
				Y: IdentityPoint.Y,
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
	t.Parallel()

	var pt JacobianPoint

	var testcases = []struct {
		name     string
		point    *JacobianPoint
		number   *ModNScalar
		expected *Point
	}{
		{
			name:   "multiply a generator point by number",
			point:  GenPoint,
			number: NewModNScalar("51c4dba2c28fc89b208550477a514c87f9d0db0354f03b7c61f08c0a0e3118a2"),
			expected: &Point{
				X: *NewFieldVal("bb6c1de01f36618ae05f7c183c22dfa8797e779f39537752c27e2dc045b0e694"),
				Y: *NewFieldVal("2f8af53270bf045f2258834b6dad7481ad6fca009d80f5b54697b08d104fc7b3"),
			},
		},
		{
			name: "multiply a random point by number",
			point: NewJacobianPoint(NewFieldVal("1fe4e60da1652de650a3b173f835a438bc94de16e4ab497eca2e899c767eaf2c"),
				NewFieldVal("dd6c126f037d77a48109e64bacdce7d37bcdd1540319d7063a20a546a321937d"), one),
			number: NewModNScalar("51c4dba2c28fc89b208550477a514c87f9d0db0354f03b7c61f08c0a0e3118a2"),
			expected: &Point{
				X: *NewFieldVal("9b4c6c9014ccd964d33c320610f219c1034d5f26d64e49c307ec3890ca33b770"),
				Y: *NewFieldVal("b0ba7b592b01f13805d2935eac63474d0d83fa29e7d8700f740d6a019135accf"),
			},
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

func TestParseRFCMessage(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		message  string
		expected *BitcoinMessage
	}{
		{
			name: "correctly formatted message",
			message: fmt.Sprintf(`-----BEGIN BITCOIN SIGNED MESSAGE-----
%s
-----BEGIN BITCOIN SIGNATURE-----
16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t

H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI=
-----END BITCOIN SIGNATURE-----
			`, Message),
			expected: &BitcoinMessage{
				Address:   "16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t",
				Data:      Message,
				Signature: []byte("H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI="),
			},
		},
		{
			name: "fancy message",
			message: fmt.Sprintf(`-----BEGIN BITCOIN SIGNED MESSAGE-----
%s
-----BEGIN BITCOIN SIGNATURE-----
16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t

H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI=
-----END BITCOIN SIGNATURE-----
			`, FancyMessage),
			expected: &BitcoinMessage{
				Address:   "16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t",
				Data:      FancyMessage,
				Signature: []byte("H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI="),
			},
		},
		{
			name: "message with misplaced fields",
			message: fmt.Sprintf(`-----BEGIN BITCOIN SIGNATURE-----
16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t

H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI=
-----END BITCOIN SIGNATURE-----
-----BEGIN BITCOIN SIGNED MESSAGE-----
%s
			`, Message),
			expected: nil,
		},
		{
			name:     "empty message",
			message:  "",
			expected: nil,
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual := ParseRFCMessage(testcase.message)
			require.Equal(t, testcase.expected, actual)
		})
	}
}

func TestSignMessageDeterministic(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		privKey       *string
		addrType      string
		message       string
		deterministic bool
		electrum      bool
		expected      *BitcoinMessage
	}{
		{
			name:          "sign message deterministically with legacy address",
			privKey:       NewStr("Ky89h1iA6vwjpD4yUaJJ3ZXnXm5iCRPpNWY4LiDJZmtU9bvQoXqb"),
			addrType:      "legacy",
			message:       Message,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				Address:   "133XqEAPNSYfAuPkjPChYLiEM64TnS6f7q",
				Data:      Message,
				Signature: []byte("HxsPQKwkQF5VWA/iEt1cszOIFJFUNqAmIZW5PRaDGWSYIQFD/sPwtqCozKd87CzrQ9huLmgtjdcLnJwpez3uhwc=")},
		},
		{
			name:          "sign message deterministically with nested segwit address",
			privKey:       NewStr("L1ztTW19cLchYbbtt9bCdyBbNZTg1GScf8NRVH1ovxpfiqUBrhKM"),
			addrType:      "nested",
			message:       Message,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				Address:   "3C7MT5Tt3HM8ZF6T14yVsbRFtiBkY1fCZS",
				Data:      Message,
				Signature: []byte("IwxiTLdDP2UwA/ST1hHo3QErhmkM4+epqAs4HLESVvigaak0gJqlU+B3oB4vxsMluKosDr1NW8ZJMA4USmwUMr0=")},
		},
		{
			name:          "sign message deterministically with segwit address",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       Message,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				Address:   "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
				Data:      Message,
				Signature: []byte("JwGZV037XaS2TOWPJ1daKxOOsn6K4nN9LuDP/gTGr7Fkebu55Lg1pX92A1TivTLoY0/ZVAvAju6Epqoc/5mY5og=")},
		},
		{
			name:          "sign fancy message deterministically with segwit address",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       FancyMessage,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				Address:   "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
				Data:      FancyMessage,
				Signature: []byte("J3RLthJCqVY5DETEpDLkep92et9dXuntiTWCxwF/lYRPa9mACkdJzT6iCq3qHox4pu9AwNR148mxs2nAqzmAcls=")},
		},
		{
			name:          "sign message deterministically with segwit address using electrum standard",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       Message,
			deterministic: true,
			electrum:      true,
			expected: &BitcoinMessage{
				Address:   "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
				Data:      Message,
				Signature: []byte("HwGZV037XaS2TOWPJ1daKxOOsn6K4nN9LuDP/gTGr7Fkebu55Lg1pX92A1TivTLoY0/ZVAvAju6Epqoc/5mY5og=")},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			pk, _ := NewPrivateKey(nil, testcase.privKey)
			actual, err := SignMessage(pk, testcase.addrType, testcase.message, testcase.deterministic, testcase.electrum)
			require.NoError(t, err)
			require.Equal(t, testcase.expected, actual)
		})
	}
}

func TestSignMessageNonDeterministic(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		privKey       *string
		addrType      string
		message       string
		deterministic bool
		electrum      bool
		expected      string
	}{
		{
			name:          "sign message non deterministically with legacy address",
			privKey:       NewStr("Ky89h1iA6vwjpD4yUaJJ3ZXnXm5iCRPpNWY4LiDJZmtU9bvQoXqb"),
			addrType:      "legacy",
			message:       Message,
			deterministic: false,
			electrum:      false,
			expected:      "133XqEAPNSYfAuPkjPChYLiEM64TnS6f7q",
		},
		{
			name:          "sign message non deterministically with nested segwit address",
			privKey:       NewStr("L1ztTW19cLchYbbtt9bCdyBbNZTg1GScf8NRVH1ovxpfiqUBrhKM"),
			addrType:      "nested",
			message:       Message,
			deterministic: false,
			electrum:      false,
			expected:      "3C7MT5Tt3HM8ZF6T14yVsbRFtiBkY1fCZS",
		},
		{
			name:          "sign message non deterministically with segwit address",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       Message,
			deterministic: false,
			electrum:      false,
			expected:      "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
		},
		{
			name:          "sign message non deterministically with uncompressed private key",
			privKey:       NewStr("5JycBec74raFLLUKJqD21cJMcTQyftgj9qjwFRxaf4NALEKqnSU"),
			addrType:      "legacy",
			message:       Message,
			deterministic: false,
			electrum:      false,
			expected:      "14f7r88uvzs6XKkQVUBGP7baxt88eig4f1",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			pk, _ := NewPrivateKey(nil, testcase.privKey)
			actual, err := SignMessage(pk, testcase.addrType, testcase.message, testcase.deterministic, testcase.electrum)
			require.NoError(t, err)
			require.Equal(t, testcase.expected, actual.Address)
		})
	}
}

func TestSignMessageErr(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		privKey       *string
		addrType      string
		message       string
		deterministic bool
		electrum      bool
		errMsg        string
	}{
		{
			name:          "sign message with uncompressed private key and nested segwit address",
			privKey:       NewStr("5JycBec74raFLLUKJqD21cJMcTQyftgj9qjwFRxaf4NALEKqnSU"),
			addrType:      "nested",
			message:       Message,
			deterministic: false,
			electrum:      false,
			errMsg:        "invalid address type",
		},
		{
			name:          "sign message with uncompressed private key and native segwit address",
			privKey:       NewStr("5JycBec74raFLLUKJqD21cJMcTQyftgj9qjwFRxaf4NALEKqnSU"),
			addrType:      "segwit",
			message:       Message,
			deterministic: false,
			electrum:      false,
			errMsg:        "invalid address type",
		},
		{
			name:          "sign message with non existent address type",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "test",
			message:       Message,
			deterministic: false,
			electrum:      false,
			errMsg:        "invalid address type",
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			pk, _ := NewPrivateKey(nil, testcase.privKey)
			_, err := SignMessage(pk, testcase.addrType, testcase.message, testcase.deterministic, testcase.electrum)
			require.EqualError(t, err, testcase.errMsg)
		})
	}
}

func TestVerifyMessage(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		message  *BitcoinMessage
		electrum bool
		expected *VerifyMessageResult
	}{
		{
			name: "verify message with legacy address",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("IEM/bGa3Vl4lZF+G12+gMMw9AeowJq0+UHMW557DuP3LcVafaeiX91w6u1/aj9TNj6/3GkHsqYtMl2X40YHL/qQ=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "03dee05815b94b373572b62be33adaaec4738b4d0a03107d0972d753b2bc64ff0e",
				Message:  "message verified to be from 1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao"},
		},
		{
			name: "verify message with nested segwit address",
			message: &BitcoinMessage{
				Address:   "34SXqp4aYmxY46nR68W5tTpD6YEHp1FKGv",
				Data:      Message,
				Signature: []byte("I0lwEpgqjrhQteZWeic539NohOyXi2DpbT16pSE7dygXXdiVpJptGW81caI2rxmuIAoig+IaebNaVCmRQNpEN7M=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "031987d146b3715ee3cd3fd0d75251ea5055f719fdd26e241f75be8b74e91a460b",
				Message:  "message verified to be from 34SXqp4aYmxY46nR68W5tTpD6YEHp1FKGv"},
		},
		{
			name: "verify message with segwit address",
			message: &BitcoinMessage{
				Address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				Data:      Message,
				Signature: []byte("J1Pgcc6VOqkcNNeiQHwjcnoYixiCM29cXUvuP6rhG338XSuaRsJpV419nbWQzpX+aVLWZZ8j/HGW6Cud3eEg+3A=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "024203f00993564099add23e0309020cdba7f33641690530b483e1bbee53f0b3b0",
				Message:  "message verified to be from bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t"},
		},
		{
			name: "verify message with segwit address and electrum standard",
			message: &BitcoinMessage{
				Address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				Data:      Message,
				Signature: []byte("H1Pgcc6VOqkcNNeiQHwjcnoYixiCM29cXUvuP6rhG338XSuaRsJpV419nbWQzpX+aVLWZZ8j/HGW6Cud3eEg+3A=")},
			electrum: true,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "024203f00993564099add23e0309020cdba7f33641690530b483e1bbee53f0b3b0",
				Message:  "message verified to be from bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t"},
		},
		{
			name: "verify fancy message with segwit address",
			message: &BitcoinMessage{
				Address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				Data:      FancyMessage,
				Signature: []byte("KHwAJ0Nmy0NCXm1mZj/S58QDfyuODZg6iSPQjSI9JBlsRAEKaJIJb5cH7s7NcPmX3tWiYTs/6lupP0/uCP2b344=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "024203f00993564099add23e0309020cdba7f33641690530b483e1bbee53f0b3b0",
				Message:  "message verified to be from bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t"},
		},
		{
			name: "verify message with segwit address and wrong signature",
			message: &BitcoinMessage{
				Address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				Data:      Message,
				Signature: []byte("I0lwEpgqjrhQteZWeic539NohOyXi2DpbT16pSE7dygXXdiVpJptGW81caI2rxmuIAoig+IaebNaVCmRQNpEN7M=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: false,
				PubKey:   "031987d146b3715ee3cd3fd0d75251ea5055f719fdd26e241f75be8b74e91a460b",
				Message:  "message failed to verify"},
		},
		{
			name: "verify message with segwit address and wrong signature and electrum standard",
			message: &BitcoinMessage{
				Address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				Data:      Message,
				Signature: []byte("I0lwEpgqjrhQteZWeic539NohOyXi2DpbT16pSE7dygXXdiVpJptGW81caI2rxmuIAoig+IaebNaVCmRQNpEN7M=")},
			electrum: true,
			expected: &VerifyMessageResult{
				Verified: false,
				PubKey:   "031987d146b3715ee3cd3fd0d75251ea5055f719fdd26e241f75be8b74e91a460b",
				Message:  "message failed to verify"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual, err := VerifyMessage(testcase.message, testcase.electrum)
			require.NoError(t, err)
			require.Equal(t, testcase.expected, actual)
		})
	}
}

func TestVerifyMessageErr(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		message  *BitcoinMessage
		electrum bool
		errMsg   string
	}{
		{
			name: "signature decode error",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("tests")},
			electrum: false,
			errMsg:   "decode error",
		},
		{
			name: "signature is too short",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("test")},
			electrum: false,
			errMsg:   "signature must be 65 bytes long",
		},
		{
			name: "signature has an unsupported header",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("LwM/bGa3Vl4lZF+G12+gMMw9AeowJq0+UHMW557DuP3LcVafaeiX91w6u1/aj9TNj6/3GkHsqYtMl2X40YHL/qQ=")},
			electrum: false,
			errMsg:   "header byte out of range",
		},
		{
			name: "signature r-value is out of range",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("IgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")},
			electrum: false,
			errMsg:   "r-value out of range",
		},
		{
			name: "signature s-value is out of range",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("IgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")},
			electrum: false,
			errMsg:   "s-value out of range",
		},
		{
			name: "invalid signature: signature R + N >= P",
			message: &BitcoinMessage{
				Address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				Data:      Message,
				Signature: []byte("LgM/bGa3Vl4lZF+G12+gMMw9AeowJq0+UHMW557DuP3LcVafaeiX91w6u1/aj9TNj6/3GkHsqYtMl2X40YHL/qQ=")},
			electrum: false,
			errMsg:   "invalid signature: signature R + N >= P",
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := VerifyMessage(testcase.message, testcase.electrum)
			require.EqualError(t, err, testcase.errMsg)
		})
	}
}
