package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"github.com/mozilla-services/mozldap"
)

func main() {
	if os.Getenv("MOZLDAPUSER") == "" || os.Getenv("MOZLDAPPASSWORD") == "" {
		log.Fatal("export env variables MOZLDAPUSER and MOZLDAPPASSWORD to log in")
	}
	cli, err := mozldap.NewClient(
		"ldap://ldap.db.scl3.mozilla.com/dc=mozilla",
		os.Getenv("MOZLDAPUSER"),
		os.Getenv("MOZLDAPPASSWORD"),
		&tls.Config{InsecureSkipVerify: true},
		true,
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("connected %s on %s:%d, tls:%v starttls:%v\n",
		cli.BaseDN, cli.Host, cli.Port, cli.UseTLS, cli.UseStartTLS)

	pubkeys, err := cli.GetUserSSHPublicKeys("mail=jvehent@mozilla.com")
	if err != nil {
		log.Fatal(err)
	}
	for _, pkey := range pubkeys {
		fmt.Println(pkey)
	}
}
