package bmt

import (
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

// BenchmarkCreateWallets measures the performance of the CreateWallets function.
func BenchmarkCreateWallets(b *testing.B) {
	tf, tfclose := testTempFile(b)
	defer tfclose()
	b.ResetTimer()
	CreateWallets(b.N, tf)
}

// BenchmarkCreateNewWalletFromWif measures the performance of wallet creation
// with a private key in hexadecimal format.
func BenchmarkCreateNewWalletFromHex(b *testing.B) {
	pk := NewByteStr("8fbbb1d88e98f161d9b01e9793bdf1230c18247197205a6cfc06621094de2cc2")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CreateNewWallet(pk, nil)
	}
}

// BenchmarkCreateNewWalletFromWif measures the performance of wallet creation
// with a private key in WIF format.
func BenchmarkCreateNewWalletFromWif(b *testing.B) {
	pk := NewStr("L237JJ2nbSesrbZHwKrXx8nGkp5qoksxhFyiaQuqC6bKv3hsJZDL")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CreateNewWallet(nil, pk)
	}
}

// BenchmarkDblPoint imeasures the performance of the Dbl method of the JacobianPoint struct.
func BenchmarkDblPoint(b *testing.B) {
	var point JacobianPoint
	p := NewJacobianPoint(
		NewFieldVal("7767299e6e84bddd0666167f51354a7e82536191f1d358314a4eba0f817a5733"),
		NewFieldVal("958e6100b13a6ebb32187280f587a4b05c90f6586c736ca70c2d23b36d680062"),
		one)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		point.Dbl(p)
	}
}

// BenchmarkAddPoints measures the performance of the Add method of the JacobianPoint struct.
func BenchmarkAddPoints(b *testing.B) {
	var point JacobianPoint
	p1 := NewJacobianPoint(
		NewFieldVal("7767299e6e84bddd0666167f51354a7e82536191f1d358314a4eba0f817a5733"),
		NewFieldVal("958e6100b13a6ebb32187280f587a4b05c90f6586c736ca70c2d23b36d680062"),
		one)
	p2 := NewJacobianPoint(
		NewFieldVal("12949c70d1c62c18a580d548efb415fb664927b464cad344322a2bbf4a7f7316"),
		NewFieldVal("3e3529824df050622e17e02d538d075791580e3db9051a2fce1d8c84cc0043ee"),
		one)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		point.Add(p1, p2)
	}
}

// BenchmarkMulGenPoint measures the performance of the Mul method of the JacobianPoint struct
// when multiplying a GenPoint with a ModNScalar.
func BenchmarkMulGenPoint(b *testing.B) {
	var point JacobianPoint
	pk := NewModNScalar("c95d8d0f41ef180b28a27e5777f5785e90ee59eb741c668749d0a226f50a851d")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		point.Mul(pk, GenPoint)
	}
}

// BenchmarkMulPoint measures the performance of the Mul method of the JacobianPoint struct
// when multiplying a random point with a ModNScalar.
func BenchmarkMulPoint(b *testing.B) {
	var point JacobianPoint
	pk := NewModNScalar("c95d8d0f41ef180b28a27e5777f5785e90ee59eb741c668749d0a226f50a851d")
	p := NewJacobianPoint(
		NewFieldVal("7767299e6e84bddd0666167f51354a7e82536191f1d358314a4eba0f817a5733"),
		NewFieldVal("958e6100b13a6ebb32187280f587a4b05c90f6586c736ca70c2d23b36d680062"),
		one)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		point.Mul(pk, p)
	}
}

// BenchmarkSignMessageDeterministic measures the performance of SignMessage function
// when signing deterministically.
func BenchmarkSignMessageDeterministic(b *testing.B) {
	pk := NewByteStr("c95d8d0f41ef180b28a27e5777f5785e90ee59eb741c668749d0a226f50a851d")
	privKey, _ := NewPrivateKey(pk, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignMessage(privKey, "segwit", Message, true, false)
	}
}

// BenchmarkSignMessageNonDeterministic measures the performance of SignMessage function
// when signing non-deterministically.
func BenchmarkSignMessageNonDeterministic(b *testing.B) {
	pk := NewByteStr("c95d8d0f41ef180b28a27e5777f5785e90ee59eb741c668749d0a226f50a851d")
	privKey, _ := NewPrivateKey(pk, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignMessage(privKey, "segwit", Message, false, false)
	}
}

// BenchmarkVerifyMessage measures the performance of VerifyMessage function
func BenchmarkVerifyMessage(b *testing.B) {
	bm := &BitcoinMessage{
		address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
		payload:   FancyMessage,
		signature: []byte("KHwAJ0Nmy0NCXm1mZj/S58QDfyuODZg6iSPQjSI9JBlsRAEKaJIJb5cH7s7NcPmX3tWiYTs/6lupP0/uCP2b344=")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyMessage(bm, false)
	}
}

// BenchmarkConvertToBits measures the performance of the ConvertToBits function.
func BenchmarkConvertToBits(b *testing.B) {
	pk := NewByteStr("c95d8d0f41ef180b28a27e5777f5785e90ee59eb741c668749d0a226f50a851d")
	buf := make([]int, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConvertToBits(*pk, &buf)
	}
}

// BenchmarkValidateKey measures the performance of scalar validation.
func BenchmarkValidateKey(b *testing.B) {
	pk := NewByteStr("c95d8d0f41ef180b28a27e5777f5785e90ee59eb741c668749d0a226f50a851d")
	var scalar ModNScalar
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateKey(pk, &scalar)
	}
}

// BenchmarkParseRFCMessage measures the performance of parsing in RFC2440-like format.
func BenchmarkParseRFCMessage(b *testing.B) {
	message := `-----BEGIN BITCOIN SIGNED MESSAGE-----
ECDSA is the most fun I have ever experienced
-----BEGIN BITCOIN SIGNATURE-----
16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t

H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI=
-----END BITCOIN SIGNATURE-----`
	var bm BitcoinMessage
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseRFCMessage(message, &bm)
	}
}

// TestCreateNewWalletFromRawPrivateKey tests the CreateNewWallet function
// with raw private keys.
func TestCreateNewWalletFromRawPrivateKey(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		privKey  *[]byte
		expected *wallet
	}{
		{
			name:    "create wallet from provided private key in raw format",
			privKey: NewByteStr("c25c21007c61110c6a2162f30aacb5e94c2a304d9104809814266067da2d78aa"),
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
			privKey: NewByteStr("af891cd2de010ece231f843fe2aebe49fdc4481473954fbe6d5f46a0a839b61e"),
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

// TestCreateNewWalletFromRawPrivateKey tests the CreateNewWallet function
// with private keys in Wallet Import Format (WIF).
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

// TestCreateNewWalletErr tests the CreateNewWallet function for error cases.
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
			privKeyRaw: NewByteStr("3a6039a639aca056ebd7cf4613a6aa6933a135f4b8e38e413d093814fdc6c1e6"),
			privKeyWif: NewStr("KyBBjqHmb5yXS8ZCPjV3J9by9qP8XuZbZMAhRLchfyMVDh24xA6v"),
			errMsg:     "cannot specify both raw and wif",
		},
		{
			name:       "provided private key is out of range",
			privKeyRaw: NewByteStr("00"),
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

// TestDblPoint tests the point doubling in Jacobian coordinates.
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

// TestParseRFCMessage tests parsing bitcoin messages in RFC2440-like format.
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
				address:   "16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t",
				payload:   Message,
				signature: []byte("H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI="),
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
				address:   "16wrm6zJek6REbxbJSLsBHehn3Lj1vo57t",
				payload:   FancyMessage,
				signature: []byte("H3x5bM2MpXK9MyLLbIGWQjZQNTP6lfuIjmPqMrU7YZ5CCm5bS9L+zCtrfIOJaloDb0mf9QBSEDIs4UCd/jou1VI="),
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
			expected: &BitcoinMessage{
				address:   "",
				payload:   "",
				signature: nil,
			},
		},
		{
			name:    "empty message",
			message: "",
			expected: &BitcoinMessage{
				address:   "",
				payload:   "",
				signature: nil,
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			var actual BitcoinMessage
			ParseRFCMessage(testcase.message, &actual)
			require.Equal(t, testcase.expected, &actual)
		})
	}
}

// TestSignMessageDeterministic tests the deterministic (RFC6979) signing of messages.
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
				address:   "133XqEAPNSYfAuPkjPChYLiEM64TnS6f7q",
				payload:   Message,
				signature: []byte("HxsPQKwkQF5VWA/iEt1cszOIFJFUNqAmIZW5PRaDGWSYIQFD/sPwtqCozKd87CzrQ9huLmgtjdcLnJwpez3uhwc=")},
		},
		{
			name:          "sign message deterministically with nested segwit address",
			privKey:       NewStr("L1ztTW19cLchYbbtt9bCdyBbNZTg1GScf8NRVH1ovxpfiqUBrhKM"),
			addrType:      "nested",
			message:       Message,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				address:   "3C7MT5Tt3HM8ZF6T14yVsbRFtiBkY1fCZS",
				payload:   Message,
				signature: []byte("IwxiTLdDP2UwA/ST1hHo3QErhmkM4+epqAs4HLESVvigaak0gJqlU+B3oB4vxsMluKosDr1NW8ZJMA4USmwUMr0=")},
		},
		{
			name:          "sign message deterministically with segwit address",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       Message,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				address:   "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
				payload:   Message,
				signature: []byte("JwGZV037XaS2TOWPJ1daKxOOsn6K4nN9LuDP/gTGr7Fkebu55Lg1pX92A1TivTLoY0/ZVAvAju6Epqoc/5mY5og=")},
		},
		{
			name:          "sign fancy message deterministically with segwit address",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       FancyMessage,
			deterministic: true,
			electrum:      false,
			expected: &BitcoinMessage{
				address:   "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
				payload:   FancyMessage,
				signature: []byte("J3RLthJCqVY5DETEpDLkep92et9dXuntiTWCxwF/lYRPa9mACkdJzT6iCq3qHox4pu9AwNR148mxs2nAqzmAcls=")},
		},
		{
			name:          "sign message deterministically with segwit address using electrum standard",
			privKey:       NewStr("L41eiqRxJBq4AMzcy49c95gjAtMEHxzV89s6NSY5Nt2R6veJYy36"),
			addrType:      "segwit",
			message:       Message,
			deterministic: true,
			electrum:      true,
			expected: &BitcoinMessage{
				address:   "bc1q8ds45ycuuqcgejj0yzpmvsdqntlx9hx6xre05k",
				payload:   Message,
				signature: []byte("HwGZV037XaS2TOWPJ1daKxOOsn6K4nN9LuDP/gTGr7Fkebu55Lg1pX92A1TivTLoY0/ZVAvAju6Epqoc/5mY5og=")},
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

// TestSignMessageNonDeterministic tests the non-deterministic signing of messages.
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
			require.Equal(t, testcase.expected, actual.address)
		})
	}
}

// TestSignMessageErr tests for errors during signing of messages.
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

// TestVerifyMessage tests the verification of messages.
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
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("IEM/bGa3Vl4lZF+G12+gMMw9AeowJq0+UHMW557DuP3LcVafaeiX91w6u1/aj9TNj6/3GkHsqYtMl2X40YHL/qQ=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "03dee05815b94b373572b62be33adaaec4738b4d0a03107d0972d753b2bc64ff0e",
				Message:  "message verified to be from 1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao"},
		},
		{
			name: "verify message with nested segwit address",
			message: &BitcoinMessage{
				address:   "34SXqp4aYmxY46nR68W5tTpD6YEHp1FKGv",
				payload:   Message,
				signature: []byte("I0lwEpgqjrhQteZWeic539NohOyXi2DpbT16pSE7dygXXdiVpJptGW81caI2rxmuIAoig+IaebNaVCmRQNpEN7M=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "031987d146b3715ee3cd3fd0d75251ea5055f719fdd26e241f75be8b74e91a460b",
				Message:  "message verified to be from 34SXqp4aYmxY46nR68W5tTpD6YEHp1FKGv"},
		},
		{
			name: "verify message with segwit address",
			message: &BitcoinMessage{
				address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				payload:   Message,
				signature: []byte("J1Pgcc6VOqkcNNeiQHwjcnoYixiCM29cXUvuP6rhG338XSuaRsJpV419nbWQzpX+aVLWZZ8j/HGW6Cud3eEg+3A=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "024203f00993564099add23e0309020cdba7f33641690530b483e1bbee53f0b3b0",
				Message:  "message verified to be from bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t"},
		},
		{
			name: "verify message with segwit address and electrum standard",
			message: &BitcoinMessage{
				address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				payload:   Message,
				signature: []byte("H1Pgcc6VOqkcNNeiQHwjcnoYixiCM29cXUvuP6rhG338XSuaRsJpV419nbWQzpX+aVLWZZ8j/HGW6Cud3eEg+3A=")},
			electrum: true,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "024203f00993564099add23e0309020cdba7f33641690530b483e1bbee53f0b3b0",
				Message:  "message verified to be from bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t"},
		},
		{
			name: "verify fancy message with segwit address",
			message: &BitcoinMessage{
				address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				payload:   FancyMessage,
				signature: []byte("KHwAJ0Nmy0NCXm1mZj/S58QDfyuODZg6iSPQjSI9JBlsRAEKaJIJb5cH7s7NcPmX3tWiYTs/6lupP0/uCP2b344=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: true,
				PubKey:   "024203f00993564099add23e0309020cdba7f33641690530b483e1bbee53f0b3b0",
				Message:  "message verified to be from bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t"},
		},
		{
			name: "verify message with segwit address and wrong signature",
			message: &BitcoinMessage{
				address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				payload:   Message,
				signature: []byte("I0lwEpgqjrhQteZWeic539NohOyXi2DpbT16pSE7dygXXdiVpJptGW81caI2rxmuIAoig+IaebNaVCmRQNpEN7M=")},
			electrum: false,
			expected: &VerifyMessageResult{
				Verified: false,
				PubKey:   "031987d146b3715ee3cd3fd0d75251ea5055f719fdd26e241f75be8b74e91a460b",
				Message:  "message failed to verify"},
		},
		{
			name: "verify message with segwit address and wrong signature and electrum standard",
			message: &BitcoinMessage{
				address:   "bc1qflpqmegknastcgs39zeza6jy23nzumayc3za2t",
				payload:   Message,
				signature: []byte("I0lwEpgqjrhQteZWeic539NohOyXi2DpbT16pSE7dygXXdiVpJptGW81caI2rxmuIAoig+IaebNaVCmRQNpEN7M=")},
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

// TestVerifyMessageErr tests for errors during the verification of messages.
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
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("tests")},
			electrum: false,
			errMsg:   "decode error",
		},
		{
			name: "signature is too short",
			message: &BitcoinMessage{
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("test")},
			electrum: false,
			errMsg:   "signature must be 65 bytes long",
		},
		{
			name: "signature has an unsupported header",
			message: &BitcoinMessage{
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("LwM/bGa3Vl4lZF+G12+gMMw9AeowJq0+UHMW557DuP3LcVafaeiX91w6u1/aj9TNj6/3GkHsqYtMl2X40YHL/qQ=")},
			electrum: false,
			errMsg:   "header byte out of range",
		},
		{
			name: "signature r-value is out of range",
			message: &BitcoinMessage{
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("IgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")},
			electrum: false,
			errMsg:   "r-value out of range",
		},
		{
			name: "signature s-value is out of range",
			message: &BitcoinMessage{
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("IgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")},
			electrum: false,
			errMsg:   "s-value out of range",
		},
		{
			name: "header byte out of range",
			message: &BitcoinMessage{
				address:   "1JeARtmwjd8smhvVcS7PW9dG7rhDXJZ4ao",
				payload:   Message,
				signature: []byte("LgM/bGa3Vl4lZF+G12+gMMw9AeowJq0+UHMW557DuP3LcVafaeiX91w6u1/aj9TNj6/3GkHsqYtMl2X40YHL/qQ=")},
			electrum: false,
			errMsg:   "header byte out of range",
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := VerifyMessage(testcase.message, testcase.electrum)
			require.EqualError(t, err, testcase.errMsg)
		})
	}
}
