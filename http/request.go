package http

import (
	"bytes"
	"net/http"
	"strconv"
)

func WebPush(info map[string]interface{}) {

	client := &http.Client{}

	body := bytes.NewReader(info["cipherText"].([]byte))
	req, _ := http.NewRequest("POST", "https://updates.push.services.mozilla.com/wpush/v1/gAAAAABYcbiQNFPuG0KM4sVpqbCNu27T44zqIGBREvT5vN6JkOz9oXtN3E2ZZ2UcCxco21sJ7rqqwuM6tt5WR3el2MEqesSZtYtcAajgQbt3siAr_In8z5UaFcfu-83Zdm22CP2GXTct", body)

	if body == nil {
		panic("To make this request you will need a body")
	}

	leng := strconv.Itoa(len(info["cipherText"].([]byte)))

	req.Header.Add("Content-Length", leng)
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("Encryption", "salt="+info["salt"].(string))
	req.Header.Add("Crypto-Key", "dh="+info["publicKey"].(string))
	req.Header.Add("Content-Encoding", "aesgcm")
	req.Header.Add("TTL", "10")
	_, err := client.Do(req)

	if err != nil {
		panic("Impossible to do this request")
	}
}
