package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/pavelkrolevets/ecdsa/ecgeneric"
	"github.com/pavelkrolevets/ecdsa/gost"
	"github.com/pavelkrolevets/ecdsa/nist"
	"golang.org/x/crypto/sha3"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
)



func main() {
	/////////
	// Tiny EC play
	/////////
	TinyEC()

	////////	
	// Gost 3412
	////////
	Gost3412()

	////////
	// SECP256k1 signature check
	////////
	Secp256k1()
}

func StandartECDSA() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %x\n", sig)

	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], sig)
	fmt.Println("signature verified:", valid)
}

func TinyEC(){
	X, Y := new(big.Int), new(big.Int)
	for i := big.NewInt(0); i.Cmp(big.NewInt(24)) == -1 ; i.Add(i, big.NewInt(1)) {
		log.Printf("K %d \n", i)
		X, Y = nist.TinyEc.ScalarBaseMult(i)
		log.Printf("Point %d, (%d, %d) \n", i, X.Uint64(), Y.Uint64())
	}
	log.Println(nist.Secp256k1.IsOnCurveGeneric(nist.Secp256k1.Gx, nist.Secp256k1.Gy))
}

func Gost3412(){
	priv := ecgeneric.BigFromHex("BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508E102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
	X, Y := gost.Gost341012512paramSetB.ScalarBaseMult(priv)
	log.Printf("Point PUBLIC(%s, %s) \n", X, Y)
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	fmt.Println("Hash of the message ", hex.EncodeToString(hash.Sum(nil)))
	r, s, _ := gost.Sign(priv, hash.Sum(nil), &gost.Gost341012512paramSetB, rand.Reader)
	log.Printf("GOST r, s signature params (%s, %s) \n", r, s)
	verify, _ := gost.Verify(hash.Sum(nil), r, s, X, Y, &gost.Gost341012512paramSetB)
	log.Println("GOST Signature verifyed ", verify)
	ecRecX, ecRecY := gost.Ecrecover(hash.Sum(nil), r, s, X, Y, &gost.Gost341012512paramSetB)
	log.Printf("Gost x, y recovered (%s, %s) \n", fmt.Sprintf("%x", ecRecX), fmt.Sprintf("%x", ecRecY))
}

func Secp256k1(){
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	fmt.Println("Hash of the message ", hex.EncodeToString(hash.Sum(nil)))

	priv_ := ecgeneric.BigFromHex("52edb68fe48aff9b5c071f076285c53ac5b1a3501139bb2cb2922b7f3923d23e")
	pubX_, pubY_ := nist.Secp256k1.ScalarBaseMult(priv_)
	log.Printf("Public key point pubX, pubY (%s, %s) \n", pubX_, pubY_)
	r_, s_, err := nist.Sign(priv_, hash.Sum(nil), &nist.Secp256k1, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("r, s (%s, %s) \n",  r_, s_)
	verify, _ := nist.Verify(hash.Sum(nil), r_, s_, pubX_, pubY_)
	log.Println("Signature verifyed ", verify)

	ecRecX, ecRecY := nist.Ecrecover(hash.Sum(nil), r_, s_, pubX_, pubY_)
	log.Printf("x, y recovered (%s, %s) \n", fmt.Sprintf("%x", ecRecX), fmt.Sprintf("%x", ecRecY))
}