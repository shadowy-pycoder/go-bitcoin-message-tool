package bmt

import (
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const WalletFilePath string = "wallets.txt"

func NewInt(s string) *big.Int {
	num, _ := new(big.Int).SetString(s, 16)
	return num
}
func NewStr(s string) *string {
	return &s
}

func BenchmarkCreateWallets(b *testing.B) {
	CreateWallets(b.N, WalletFilePath)
	err := os.Remove(WalletFilePath)
	if err != nil {
		b.Fatal(err)
	}
}

func TestCreateNewWalletFromRawPrivateKey(t *testing.T) {
	var testcases = []struct {
		privKey  *big.Int
		expected *Wallet
	}{
		{
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
		actual, err := CreateNewWallet(testcase.privKey, nil)
		require.NoError(t, err)
		require.Equal(t, actual, testcase.expected)
	}
}

func TestCreateNewWalletFromWifPrivateKey(t *testing.T) {
	var testcases = []struct {
		privKey  *string
		expected *Wallet
	}{
		{
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
		actual, err := CreateNewWallet(nil, testcase.privKey)
		require.NoError(t, err)
		require.Equal(t, actual, testcase.expected)
	}
}

func TestCreateNewWalletErr(t *testing.T) {
	var testcases = []struct {
		privKeyRaw *big.Int
		privKeyWif *string
		errMsg     string
	}{
		{
			privKeyRaw: NewInt("3a6039a639aca056ebd7cf4613a6aa6933a135f4b8e38e413d093814fdc6c1e6"),
			privKeyWif: NewStr("KyBBjqHmb5yXS8ZCPjV3J9by9qP8XuZbZMAhRLchfyMVDh24xA6v"),
			errMsg:     "cannot specify both raw and wif",
		},
		{
			privKeyRaw: new(big.Int).Add(Secp256k1.NCurve, one),
			privKeyWif: nil,
			errMsg:     "scalar is out of range",
		},
		{
			privKeyRaw: nil,
			privKeyWif: NewStr("test"),
			errMsg:     "failed decoding wif string",
		},
		{
			privKeyRaw: nil,
			privKeyWif: NewStr("KyBBjqHmb5yXS8ZCPjV3J9by9qP8XuZbZMAhRLchfyMVDh24xA6"),
			errMsg:     "invalid wif checksum",
		},
	}
	for _, testcase := range testcases {
		_, err := CreateNewWallet(testcase.privKeyRaw, testcase.privKeyWif)
		require.EqualError(t, err, testcase.errMsg)
	}
}

func TestCreateNewWalletRandom(t *testing.T) {
	wallet, err := CreateNewWallet(nil, nil)
	require.NoError(t, err)
	w, err := CreateNewWallet(wallet.PrivKey.Raw, nil)
	require.NoError(t, err)
	require.Equal(t, wallet.PrivKey.Wif, w.PrivKey.Wif)
}
