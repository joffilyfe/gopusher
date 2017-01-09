package helper

func PadPayload(payload string) string {
	s := string(byte(0x00))
	s += string(byte(0x00))
	s += payload
	return s
}
