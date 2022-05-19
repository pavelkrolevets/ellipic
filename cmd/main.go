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
)



func main() {
	// Tiny EC play
	X, Y := new(big.Int), new(big.Int)
	for i := big.NewInt(0); i.Cmp(big.NewInt(24)) == -1 ; i.Add(i, big.NewInt(1)) {
		log.Printf("K %d \n", i)
		X, Y = nist.TinyEc.ScalarBaseMult(i)
		log.Printf("Point %d, (%d, %d) \n", i, X.Uint64(), Y.Uint64())
	}
	log.Println(nist.Secp256k1.IsOnCurveGeneric(nist.Secp256k1.Gx, nist.Secp256k1.Gy))

	// Secp256k1 check 
	pubX, pubY := new(big.Int), new(big.Int)
	priv := ecgeneric.BigFromHex("52edb68fe48aff9b5c071f076285c53ac5b1a3501139bb2cb2922b7f3923d23e")
	pubX, pubY = nist.Secp256k1.ScalarBaseMult(priv)
	log.Printf("Point %d, (%s, %s) \n", 2, fmt.Sprintf("%x", pubX), fmt.Sprintf("%x", pubY))
	
	//Gost ex1 check
	priv = ecgeneric.BigFromHex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	X, Y = gost.GostEx1.ScalarBaseMult(priv)
	log.Printf("Point %d, (%s, %s) \n", 2, fmt.Sprintf("%x", X), fmt.Sprintf("%x", Y))
	m := []byte("Hello signature!")
	hash := sha3.New256()
	hash.Write(m)
	fmt.Println("Hash of the message ", hex.EncodeToString(hash.Sum(nil)))
	r, s, err := gost.Sign(priv, hash.Sum(nil), &gost.GostEx1, rand.Reader)
	log.Printf("GOST r, s signature params (%s, %s) \n", fmt.Sprintf("%x", r), fmt.Sprintf("%x", s))
	verify, _ := gost.Verify(hash.Sum(nil), r, s, X, Y, &gost.GostEx1)
	log.Println("GOST Signature verifyed ", verify)

	// SECP256k1 signature check
	m = []byte("Hello signature!")
	hash = sha3.New256()
	hash.Write(m)
	fmt.Println("Hash of the message ", hex.EncodeToString(hash.Sum(nil)))
	priv_, pubX, pubY, err := ecgeneric.GenerateKey(nist.Secp256k1, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	r, s, err = nist.Sign(new(big.Int).SetBytes(priv_), hash.Sum(nil), &nist.Secp256k1, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("r, s signature params (%s, %s) \n", fmt.Sprintf("%x", r), fmt.Sprintf("%x", s))
	verify, _ = nist.Verify(hash.Sum(nil), r, s, pubX, pubY)
	log.Println("Signature verifyed ", verify)
}
