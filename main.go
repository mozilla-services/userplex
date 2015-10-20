// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	// modules
	"github.com/mozilla-services/userplex/modules"
	//_ "github.com/mozilla-services/userplex/modules/authorizedkeys"
	_ "github.com/mozilla-services/userplex/modules/aws"
	//_ "github.com/mozilla-services/userplex/modules/datadog"

	"github.com/mozilla-services/mozldap"
	"gopkg.in/yaml.v2"
)

type conf struct {
	Ldap struct {
		Uri, Username, Password string
		Insecure, Starttls      bool
	}
	UidMap []struct {
		LdapUid string
		UsedUid string
	}

	Modules []modules.Configuration
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

	// load the local configuration file
	fd, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(fd, &conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// instanciate an ldap client
	cli, err := mozldap.NewClient(
		conf.Ldap.Uri,
		conf.Ldap.Username,
		conf.Ldap.Password,
		&tls.Config{InsecureSkipVerify: conf.Ldap.Insecure},
		conf.Ldap.Starttls)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("connected %s on %s:%d, tls:%v starttls:%v\n", cli.BaseDN, cli.Host, cli.Port, cli.UseTLS, cli.UseStartTLS)

	// store the value of dryrun and the ldap client
	// in the configuration of each module
	for i := range conf.Modules {
		conf.Modules[i].DryRun = *dryrun
		conf.Modules[i].LdapCli = cli
	}

	// run each module in the order it appears in the configuration
	for _, modconf := range conf.Modules {
		if _, ok := modules.Available[modconf.Name]; !ok {
			log.Printf("[warning] %s module not registered, skipping it", modconf.Name)
			continue
		}
		log.Println("[info] invoking module", modconf.Name)
		run := modules.Available[modconf.Name].NewRun(modconf)
		err = run.Run()
		if err != nil {
			log.Printf("[error] %s module failed with error: %v", modconf.Name, err)
		}
	}
}
