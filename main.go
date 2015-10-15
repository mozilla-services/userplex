package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/mozilla-services/mozldap"
	"gopkg.in/yaml.v2"
)

type conf struct {
	Ldap struct {
		Uri, Username, Password string
		Insecure, Starttls      bool
	}
	SSH []struct {
		Location   string
		LdapGroups []string
	}
	AWS []struct {
		Profile, AccessKey, SecretKey string
		LdapGroups                    []string
		Assign_Roles                  []string
	}
	Datadog []struct {
		LdapGroups     []string
		ApiKey, AppKey string
	}
}

func main() {
	var (
		err  error
		conf conf
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s - Manage users in various SaaS based on a LDAP source\n"+
			"Usage: %s -c config.yaml\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	var config = flag.String("c", "config.yaml", "Load configuration from file")
	var dryrun = flag.Bool("dry", false, "Dry run, don't create/delete, just show stuff")
	flag.Parse()

	fd, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(fd, &conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	cli, err := mozldap.NewClient(conf.Ldap.Uri, conf.Ldap.Username, conf.Ldap.Password,
		&tls.Config{InsecureSkipVerify: conf.Ldap.Insecure}, conf.Ldap.Starttls)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("connected %s on %s:%d, tls:%v starttls:%v\n",
		cli.BaseDN, cli.Host, cli.Port, cli.UseTLS, cli.UseStartTLS)

	for _, ssh := range conf.SSH {
		fmt.Println(ssh.Location)
		users, err := cli.GetUsersInGroups(ssh.LdapGroups)
		if err != nil {
			log.Fatal(err)
		}
		for _, user := range users {
			fmt.Printf("\t%s\n", user)
			pubkeys, err := cli.GetUserSSHPublicKeys(strings.Split(user, ",")[0])
			if err != nil {
				log.Fatal(err)
			}
			for _, pkey := range pubkeys {
				fmt.Printf("\t\t%s\n", pkey)
			}
		}
	}
	if *dryrun {
		os.Exit(0)
	}
}
