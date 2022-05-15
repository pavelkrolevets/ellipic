package gost

import (
	"math/big"
	"github.com/pavelkrolevets/ecdsa/ecgeneric"
)

var	GostEx1 = ecgeneric.CurveParams{
	P:      ecgeneric.BigFromHex("8000000000000000000000000000000000000000000000000000000000000431"),
	N:      ecgeneric.BigFromHex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
	A:      big.NewInt(7),
	B:      ecgeneric.BigFromHex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
	Gx:     ecgeneric.BigFromHex("2"),
	Gy:     ecgeneric.BigFromHex("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
	BitSize: 256,
	Name:   "GostEx1",
}