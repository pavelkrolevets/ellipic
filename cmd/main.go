package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/pavelkrolevets/ecdsa/nist"
	"github.com/pavelkrolevets/ecdsa/gost"
	"golang.org/x/crypto/sha3"
)



func main() {
	m_b := []byte("Hello signature!")
	h_m_b := sha3.New256()
	h_m_b.Write(m_b)
	fmt.Println(hex.EncodeToString(h_m_b.Sum(nil)))

	pub_k_X, pub_k_Y := new(big.Int), new(big.Int)
	for i := 0; i < 24; i++ {
		pub_k_X, pub_k_Y = nist.TinyEc.AddPointsGeneric(nist.TinyEc.Gx, nist.TinyEc.Gy, pub_k_X, pub_k_Y)
		log.Printf("Point %d, (%d, %d) \n", i, pub_k_X.Uint64(), pub_k_Y.Uint64())
	}


	log.Println(nist.Secp256k1.IsOnCurveGeneric(nist.Secp256k1.Gx, nist.Secp256k1.Gy))


	// pub_k_X, pub_k_Y = new(big.Int), new(big.Int)
	// for i := 0; i < 24; i++ {
	// 	pub_k_X, pub_k_Y = ecgeneric.Secp256k1.AddPointsGeneric(ecgeneric.Secp256k1.Gx, ecgeneric.Secp256k1.Gy, pub_k_X, pub_k_Y)
	// 	log.Printf("Point %d, (%s, %s) \n", 2, fmt.Sprintf("%x", pub_k_X), fmt.Sprintf("%x", pub_k_Y))
	// }

	// priv_k, pub_k_X, pub_k_Y, err := ecgeneric.GenerateKey(ecgeneric.Secp256k1, rand.Reader)
	// if err!= nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("Point on curve, (%s, %s) \n", fmt.Sprintf("%x", pub_k_X), fmt.Sprintf("%x", pub_k_Y))
	// log.Printf("Private key %s", hex.EncodeToString(priv_k))

	// secp256k1 check 
	priv, err := hex.DecodeString("52edb68fe48aff9b5c071f076285c53ac5b1a3501139bb2cb2922b7f3923d23e")
	if err != nil {
		log.Fatal(err)
	}
	pub_k_X, pub_k_Y = nist.Secp256k1.ScalarBaseMult(priv)
	log.Printf("Point %d, (%s, %s) \n", 2, fmt.Sprintf("%x", pub_k_X), fmt.Sprintf("%x", pub_k_Y))
	
	//Gost ex1 check
	priv, err = hex.DecodeString("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	if err != nil {
		log.Fatal(err)
	}
	pub_k_X, pub_k_Y = gost.GostEx1.ScalarBaseMult(priv)
	log.Printf("Point %d, (%s, %s) \n", 2, fmt.Sprintf("%x", pub_k_X), fmt.Sprintf("%x", pub_k_Y))
}
