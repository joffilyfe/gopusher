package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/joffilyfe/gopusher/helper"
	"math/big"
)

type ECDH struct {
	curve  elliptic.Curve
	X      *big.Int
	Y      *big.Int
	D      []byte
	Public []byte
}

func NewECDH(c elliptic.Curve) *ECDH {
	return &ECDH{curve: c}
}

// Set up keys for an instance of ECDH
func (e *ECDH) GenerateKeys() error {
	private, x, y, err := elliptic.GenerateKey(e.curve, rand.Reader)

	if err != nil {
		return errors.New("Unable to generate keys")
	}

	e.X = x
	e.Y = y
	e.D = private

	return nil
}

// Generate a shared secret key based in Public points and it owns secret bytes
func (e ECDH) GenerateSharedSecret(x, y *big.Int) ([]byte, error) {
	secret, _ := e.curve.ScalarMult(x, y, e.D)
	return secret.Bytes(), nil
}

// Return an buffer array with a Public Key
func (e ECDH) GetPublicKey() []byte {
	return elliptic.Marshal(e.curve, e.X, e.Y)
}

func (e *ECDH) SetPrivateKey(data string) {
	i := helper.CreateBigInt(data)

	e.D = i.Bytes()
}

// Public shared
type PublicKey struct {
	curve elliptic.Curve
	X, Y  *big.Int
	Arr   []byte
}

func NewPuclicKey(c elliptic.Curve, info []byte) *PublicKey {
	return &PublicKey{curve: c, Arr: info}
}

func (p *PublicKey) Parse() {
	x, y := elliptic.Unmarshal(p.curve, p.Arr)

	p.X = x
	p.Y = y
}
