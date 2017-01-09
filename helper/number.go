package helper

import (
	"math/big"
)

func DecodeToInt(data string) *big.Int {
	b := Decode(data)
	i := new(big.Int)
	i.SetBytes(b)
	return i
}

func CreateBigInt(data string) *big.Int {
	d := new(big.Int)
	d.SetString(data, 10)

	return d
}
