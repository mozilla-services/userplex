// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package main

//go:generate ./version.sh

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	// modules
	"github.com/mozilla-services/userplex/modules"
	_ "github.com/mozilla-services/userplex/modules/authorizedkeys"
	_ "github.com/mozilla-services/userplex/modules/aws"
	_ "github.com/mozilla-services/userplex/modules/datadog"

	"github.com/gorhill/cronexpr"
	"github.com/mozilla-services/mozldap"
	"gopkg.in/yaml.v2"
)

type conf struct {
	Cron string
	Ldap struct {
		URI, Username, Password, TLSCert, TLSKey, CACert string
		Insecure, Starttls                               bool
		cli                                              mozldap.Client `yaml:"-",json:"-"`
	}
	Notifications struct {
		Email struct {
			Host, From, Cc, ReplyTo string
			Port                    int
			Auth                    struct {
				User, Pass string
			}
		}
	}
	UIDMap []struct {
		LdapUID  string
		LocalUID string
	}

	Modules []modules.Configuration
}

var config = flag.String("c", "config.yaml", "Load configuration from file")
var dryrun = flag.Bool("dry", false, "Dry run, don't create/delete, just show stuff")
var drynotif = flag.Bool("drynotif", false, "Same as dry run, but sends notifications out")
var once = flag.Bool("once", false, "Run only once and exit, don't under the cron loop")
var runmod = flag.String("module", "all", "Module to run. if 'all', run all available modules (default)")
var showVersion = flag.Bool("V", false, "Show version and exit")

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
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *drynotif {
		*dryrun = true
	}

	// load the local configuration file
	fd, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(fd, &conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// just run once
	if *once {
		run(conf)
		return
	}

	// infinite loop, wake up at the cron period
	for {
		cexpr, err := cronexpr.Parse(conf.Cron)
		if err != nil {
			log.Fatalf("failed to parse cron string %q: %v", conf.Cron, err)
		}
		// sleep until the next run is scheduled to happen
		nrun := cexpr.Next(time.Now())
		waitduration := nrun.Sub(time.Now())
		log.Printf("[info] next run will start at %v (in %v)", nrun, waitduration)
		time.Sleep(waitduration)

		run(conf)
	}
}

func run(conf conf) {
	var (
		cli mozldap.Client
		err error
	)
	// instanciate an ldap client
	if conf.Ldap.TLSCert != "" && conf.Ldap.TLSKey != "" {
		cli, err = mozldap.NewTLSClient(
			conf.Ldap.URI,
			conf.Ldap.Username,
			conf.Ldap.Password,
			conf.Ldap.TLSCert,
			conf.Ldap.TLSKey,
			conf.Ldap.CACert,
			&tls.Config{InsecureSkipVerify: conf.Ldap.Insecure})
	} else {
		cli, err = mozldap.NewClient(
			conf.Ldap.URI,
			conf.Ldap.Username,
			conf.Ldap.Password,
			conf.Ldap.CACert,
			&tls.Config{InsecureSkipVerify: conf.Ldap.Insecure},
			conf.Ldap.Starttls)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	log.Printf("connected %s on %s:%d, tls:%v starttls:%v\n", cli.BaseDN, cli.Host, cli.Port, cli.UseTLS, cli.UseStartTLS)
	conf.Ldap.cli = cli

	// Channel where modules publish their notifications
	// which are aggregated and sent by the main program
	notifchan := make(chan modules.Notification)
	notifdone := make(chan bool)
	go processNotifications(conf, notifchan, notifdone)

	// store the value of dryrun and the ldap client
	// in the configuration of each module
	for i := range conf.Modules {
		conf.Modules[i].DryRun = *dryrun
		conf.Modules[i].LdapCli = cli
		conf.Modules[i].Notify.Channel = notifchan
	}

	// run each module in the order it appears in the configuration
	for _, modconf := range conf.Modules {
		if *runmod != "all" && *runmod != modconf.Name {
			continue
		}
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
	// Modules are done, close the notification channel to tell the goroutine
	// that it can aggregate and send them, and wait for notifdone to come back
	close(notifchan)
	<-notifdone
}
