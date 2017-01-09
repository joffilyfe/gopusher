package helper

import (
	"encoding/base64"
	"strings"
)

func Decode(data string) []byte {
	b, _ := base64.StdEncoding.DecodeString(data)
	return b
}

func Encode(data []byte) string {
	s := base64.URLEncoding.EncodeToString(data)
	s = strings.Replace(s, "+", "-", -1)
	s = strings.Replace(s, "/", "_", -1)
	s = strings.Trim(s, "=")

	return s
}
