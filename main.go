package main

import (
	"github.com/joffilyfe/gopusher/encrypt"
	"github.com/joffilyfe/gopusher/http"
)

func main() {
	// Browser UA Keys
	UserAuth := "L9jUGA2kZeTg+J4CHOlLrg=="
	UserPublic := "BImKJXbRS9TJzjIIebgVibmjh8OxPMQa1J8uWIIEklrqjVXppo4KW4wu1GYkvp0BYttt7uG0t5m6bfGBkB3EvvU="

	result := encrypt.Encrypt(UserPublic, UserAuth, "Message with payload")

	http.WebPush(result)

}
