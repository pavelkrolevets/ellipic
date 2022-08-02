package ecgeneric_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric"
	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric/gost"
	"github.com/pavelkrolevets/gost-elliptic/src/ecgeneric/nist"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var (
	testmsg     = hexutil.MustDecode("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
	testsig     = hexutil.MustDecode("0x90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
	testpubkey  = hexutil.MustDecode("0x04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
	testpubkeyc = hexutil.MustDecode("0x02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a")
)

func Benchmark_gost_recover(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMult(priv)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	r, s, _ := gost.Sign(priv, hash.Sum(nil), &gost.Gost341012512paramSetA, rand.Reader)
	verify, _ := gost.Verify(hash.Sum(nil), r, s, X, Y, &gost.Gost341012512paramSetA)
	require.Equal(b, true, verify)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_recover_generic", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			ecRecX, ecRecY := gost.Ecrecover(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, ecRecX, X)
			require.Equal(b, ecRecY, Y)
		}
	})
}

func Benchmark_gost_recover_j(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMultJ(priv.Bytes())
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	r, s, _ := gost.SignJ(priv, hash.Sum(nil), &gost.Gost341012512paramSetA, rand.Reader)
	verify, _ := gost.VerifyJ(hash.Sum(nil), r, s, X, Y, &gost.Gost341012512paramSetA)
	require.Equal(b, true, verify)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_recover_Jacobian", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			ecRecX, ecRecY := gost.EcrecoverJ(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, ecRecX, X)
			require.Equal(b, ecRecY, Y)
		}
	})
}


func Benchmark_gost_recover_Gost34102001paramSetA(b *testing.B) {
	priv := ecgeneric.BigFromHex("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77")
	X, Y := gost.Gost34102001paramSetA.ScalarBaseMult(priv)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	r, s, _ := gost.Sign(priv, hash.Sum(nil), &gost.Gost34102001paramSetA, rand.Reader)
	verify, _ := gost.Verify(hash.Sum(nil), r, s, X, Y, &gost.Gost34102001paramSetA)
	require.Equal(b, true, verify)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecRecX, ecRecY := gost.Ecrecover(msg, r, s, X, Y, &gost.Gost34102001paramSetA)
			require.Equal(b, ecRecX, X)
			require.Equal(b, ecRecY, Y)
		}
	})
}

func Benchmark_gost_recover_j_Gost34102001paramSetA(b *testing.B) {
	priv := ecgeneric.BigFromHex("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77")
	X, Y := gost.Gost34102001paramSetA.ScalarBaseMultJ(priv.Bytes())
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	r, s, _ := gost.SignJ(priv, hash.Sum(nil), &gost.Gost34102001paramSetA, rand.Reader)
	verify, _ := gost.VerifyJ(hash.Sum(nil), r, s, X, Y, &gost.Gost34102001paramSetA)
	require.Equal(b, true, verify)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecRecX, ecRecY := gost.EcrecoverJ(msg, r, s, X, Y, &gost.Gost34102001paramSetA)
			require.Equal(b, ecRecX, X)
			require.Equal(b, ecRecY, Y)
		}
	})
}

func Benchmark_gost_sign(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMult(priv)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_sign", func(b *testing.B) {
		for i := 0; i < 100; i++ {
			r, s, _ := gost.Sign(priv, msg, &gost.Gost341012512paramSetA, rand.Reader)
			verify, _ := gost.Verify(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, true, verify)
		}
	})
}

func Benchmark_gost_sign_2001(b *testing.B) {
	priv := ecgeneric.BigFromHex("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77")
	X, Y := gost.Gost34102001paramSetA.ScalarBaseMult(priv)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_sign", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			r, s, _ := gost.Sign(priv, msg, &gost.Gost34102001paramSetA, rand.Reader)
			verify, _ := gost.Verify(msg, r, s, X, Y, &gost.Gost34102001paramSetA)
			require.Equal(b, true, verify)
		}
	})
}


func Benchmark_gost_sign_j(b *testing.B) {
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetA.ScalarBaseMultJ(priv.Bytes())
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)

	b.ResetTimer()
	b.Run("gost_sign", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			r, s, _ := gost.SignJ(priv, msg, &gost.Gost341012512paramSetA, rand.Reader)
			verify, _ := gost.VerifyJ(msg, r, s, X, Y, &gost.Gost341012512paramSetA)
			require.Equal(b, true, verify)
		}
	})
}

func Benchmark_gost_sign_j_2001(b *testing.B) {
	priv := ecgeneric.BigFromHex("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77")
	X, Y := gost.Gost34102001paramSetA.ScalarBaseMultJ(priv.Bytes())
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)
	r, s, _ := gost.SignJ(priv, msg, &gost.Gost34102001paramSetA, rand.Reader)
	b.ResetTimer()
	b.Run("gost_sign", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			verify, _ := gost.VerifyJ(msg, r, s, X, Y, &gost.Gost34102001paramSetA)
			require.Equal(b, true, verify)
		}
	})
}

func Benchmark_secp256k1_sign(b *testing.B) {
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	msg := hash.Sum(nil)
	priv_ := ecgeneric.BigFromHex("52edb68fe48aff9b5c071f076285c53ac5b1a3501139bb2cb2922b7f3923d23e")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = nist.Sign(priv_, msg, &nist.Secp256k1, rand.Reader)
		}
	})
	
}
func Benchmark_nist_sign(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	b.ResetTimer()
	b.Run("nist_sign_verify", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			valid := ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s)
			require.Equal(b, true, valid)
		}
	})
}

func Benchmark_gost_sign_STD(b *testing.B) {
	privateKey, err := ecgeneric.GenerateKey(&gost.Gost34102001paramSetA, rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))
	r, s, _ := gost.SignSTD(rand.Reader, privateKey, hash[:])
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			valid := gost.VerifySTD(&privateKey.PublicKey, hash[:], r, s)
			require.Equal(b, true, valid)
		}
	})
}

func Benchmark_gost_recover_STD(b *testing.B) {
	privateKey, err := ecgeneric.GenerateKey(&gost.Gost34102001paramSetA, rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	r, s, _ := gost.SignSTD(rand.Reader, privateKey, hash[:])
	valid := gost.VerifySTD(&privateKey.PublicKey, hash[:], r, s)
	require.Equal(b, true, valid)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecRecX, ecRecY := gost.EcrecoverSTD(&privateKey.PublicKey, &gost.Gost34102001paramSetA, hash[:], r, s)
			require.Equal(b, ecRecX, privateKey.PublicKey.X)
			require.Equal(b, ecRecY, privateKey.PublicKey.Y)
		}
	})
}

func Benchmark_nist_ecrecover(b *testing.B) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB)  {
		for pb.Next() {
			ecRecX, ecRecY := nist.EcrecoverSTD(&privateKey.PublicKey, curve, hash[:], r, s)
			require.Equal(b, ecRecX, privateKey.PublicKey.X)
			require.Equal(b, ecRecY, privateKey.PublicKey.Y)	
		}
	})
}

func Benchmark_nist_ecrecover_p256(b *testing.B) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	b.Log("Pub Key X ", privateKey.PublicKey.X.String())
	b.Log("Pub Key Y ", privateKey.PublicKey.Y.String())
	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	b.ResetTimer()
	b.Run("nist_sign_recover_p256", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			ecRecX, ecRecY := nist.EcrecoverSTD(&privateKey.PublicKey, curve, hash[:], r, s)
			require.Equal(b, ecRecX, privateKey.PublicKey.X)
			require.Equal(b, ecRecY, privateKey.PublicKey.Y)	
		}
	})
}


func BenchmarkEcrecoverEthSecp265k1Signature(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ecgeneric.Ecrecover(testmsg, testsig); err != nil {
			b.Fatal("ecrecover error", err)
		}
	}
}
