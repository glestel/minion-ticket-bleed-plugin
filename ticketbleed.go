package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"os"
)


func main() {
	var Port = "443"

	if len(os.Args) < 2 {
		fmt.Println(os.Args[0], "example.com (443)")
		return
	}

	if len(os.Args) == 3 {
		Port = os.Args[2]
	}

	var FQDN = os.Args[1]
	var Target = FQDN + ":" + Port

	conf := &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
	}

	conn, err := tls.Dial("tcp", Target, conf)
//	conn, err := tls.DialWithDialer("tcp", Target, conf)
	if err != nil {
		log.Fatalln("Failed to connect:", err)
	}
	conn.Close()

	conn, err = tls.Dial("tcp", Target, conf)
	if err != nil && strings.Contains(err.Error(), "unexpected message") {
		fmt.Println(Target, "KO")
	} else if err != nil {
		log.Fatalln("Failed to reconnect:", err)
	} else {
		fmt.Println(Target, "OK")
		conn.Close()
	}
}
