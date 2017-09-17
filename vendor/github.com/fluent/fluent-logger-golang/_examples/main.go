package main

import (
	"fmt"
	"log"
	"time"

	"../fluent"
)

func main() {
	logger, err := fluent.New(fluent.Config{FluentPort: 24224, FluentHost: "127.0.0.1"})
	if err != nil {
		fmt.Println(err)
	}
	defer logger.Close()
	tag := "myapp.access"
	var data = map[string]string{
		"foo":  "bar",
		"hoge": "hoge"}
	for i := 0; i < 100; i++ {
		e := logger.Post(tag, data)
		if e != nil {
			log.Println("Error while posting log: ", e)
		} else {
			log.Println("Success to post log")
		}
		time.Sleep(1000 * time.Millisecond)
	}
}
