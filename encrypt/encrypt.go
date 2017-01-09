package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/joffilyfe/gopusher/ecc"
	"github.com/joffilyfe/gopusher/helper"
	"golang.org/x/crypto/hkdf"
	"io"
)

// Generate an array of bytes with random seed
func GenerateBytes(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

// Generate context for encryption
// It is based on section 4.2 of RFC
func GenerateContext(clientPublic, serverPublic []byte) ([]byte, error) {
	if len(clientPublic) != 65 {
		return []byte{0}, errors.New("The Client Public key need be a 65 byte length")
	}

	if len(serverPublic) != 65 {
		return []byte{0}, errors.New("The Client Public key need be a 65 byte length")
	}

	context := make([]byte, 0)
	context = append(context, []byte{0x00, 0x00, 65}...)
	context = append(context, clientPublic...)
	context = append(context, []byte{0x00, 65}...)
	context = append(context, serverPublic...)

	return context, nil
}

// Create an encoded info
func CreateInfo(infoType string, context []byte) string {
	if len(context) != 135 {
		panic("The context requires 135 of length.")
	}

	s := "Content-Encoding: "
	s += infoType
	s += string(byte(0))
	s += "P-256"
	s += string(context)

	return s
}

// Generate a Secured Key
func Hkdf(salt, ikm, info []byte, lenght int) []byte {
	hash := sha256.New
	pkr := hkdf.New(hash, ikm, salt, info)

	key := make([]byte, lenght)
	n, err := io.ReadFull(pkr, key)

	if n != len(key) || err != nil {
		panic("Impossible to generate HKDF key")
	}

	return key
}

func Encrypt(clientPublicKey, clientAuthToken, text string) map[string]interface{} {
	user_agent := ecc.NewPuclicKey(elliptic.P256(), helper.Decode(clientPublicKey))
	user_agent.Parse()

	// Local Keys
	ecdh := ecc.NewECDH(elliptic.P256())
	ecdh.GenerateKeys()

	// Shared secret
	secret, _ := ecdh.GenerateSharedSecret(user_agent.X, user_agent.Y)

	// Generate a random salt with bytes
	salt := GenerateBytes(16)

	// Generate IKM
	ikm := Hkdf(helper.Decode(clientAuthToken), secret, []byte("Content-Encoding: auth\x00"), 32)

	// Generate Context
	context, _ := GenerateContext(helper.Decode(clientPublicKey), ecdh.GetPublicKey())

	// Crrate content Encryption Info
	contentEncryptionKeyInfo := CreateInfo("aesgcm", context)
	contentEncryptionKey := Hkdf(salt, ikm, []byte(contentEncryptionKeyInfo), 16)

	// Creating Nonce
	nonceInfo := CreateInfo("nonce", context)
	nonce := Hkdf(salt, ikm, []byte(nonceInfo), 12)

	// Generate encrypted payload
	block, _ := aes.NewCipher(contentEncryptionKey)
	aesgcm, _ := cipher.NewGCM(block)

	cipherText := aesgcm.Seal(nil, nonce, []byte(helper.PadPayload(text)), nil)

	result := make(map[string]interface{})

	result["cipherText"] = cipherText
	result["salt"] = helper.Encode(salt)
	result["publicKey"] = helper.Encode(ecdh.GetPublicKey())

	return result

}
