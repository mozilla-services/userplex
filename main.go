// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package main // import "go.mozilla.org/userplex"

//go:generate ./version.sh

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	// modules
	"go.mozilla.org/userplex/modules"
	_ "go.mozilla.org/userplex/modules/authorizedkeys"
	_ "go.mozilla.org/userplex/modules/aws"
	_ "go.mozilla.org/userplex/modules/datadog"

	"github.com/gorhill/cronexpr"
	"go.mozilla.org/mozldap"
	"gopkg.in/yaml.v2"
)

type conf struct {
	Cron string
	Ldap struct {
		URI, Username, Password string
		TLSCert, TLSKey, CACert string
		Insecure, Starttls      bool
		cli                     mozldap.Client `yaml:"-",json:"-"`
	}
	Notifications struct {
		Email struct {
			Host, From, Cc,
			ReplyTo, Subject string
			Port int
			Auth struct {
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

var config = flag.String("c", "", "Load configuration from file. Use stdin if omitted.")
var applyChanges = flag.Bool("applyChanges", false, "By default, Userplex runs in dry mode. Set this flag to apply changes.")
var notifyUsers = flag.Bool("notifyUsers", false, "If set, Userplex will send email notifications to users when changes are applied.")
var once = flag.Bool("once", false, "Run only once and exit, don't enter the cron loop")
var runmod = flag.String("module", "all", "Module to run. if 'all', run all available modules (default)")
var showVersion = flag.Bool("V", false, "Show version and exit")
var debug = flag.Bool("D", false, "Enable debug logging")
var resetUsers = flag.String("reset", "", "Reset an LDAP user's userplexed accounts")

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

	// load the local configuration file
	var data []byte
	if *config == "" {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(*config)
	}
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// just run once
	if *once || conf.Cron == "disabled" {
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
	tlsconf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: conf.Ldap.Insecure,
		ServerName:         cli.Host,
	}
	if len(conf.Ldap.TLSCert) > 0 && len(conf.Ldap.TLSKey) > 0 {
		cert, err := tls.X509KeyPair([]byte(conf.Ldap.TLSCert), []byte(conf.Ldap.TLSKey))
		if err != nil {
			log.Fatal(err)
		}
		tlsconf.Certificates = []tls.Certificate{cert}
	}
	if len(conf.Ldap.CACert) > 0 {
		ca := x509.NewCertPool()
		if ok := ca.AppendCertsFromPEM([]byte(conf.Ldap.CACert)); !ok {
			log.Fatal("failed to import CA Certificate")
		}
		tlsconf.RootCAs = ca
	}
	cli, err = mozldap.NewClient(
		conf.Ldap.URI,
		conf.Ldap.Username,
		conf.Ldap.Password,
		tlsconf,
		conf.Ldap.Starttls,
	)
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

	// store configuration parameters for each module, including
	// the values of notifyUsers, applyChanges, debug, the ldap
	// client and the notification channel
	for i := range conf.Modules {
		conf.Modules[i].ApplyChanges = *applyChanges
		conf.Modules[i].NotifyUsers = *notifyUsers
		conf.Modules[i].LdapCli = cli
		conf.Modules[i].Notify.Channel = notifchan
		conf.Modules[i].Debug = *debug
		conf.Modules[i].ResetUsers = *resetUsers
	}

	moduleHasRun := make(map[string]bool)

	// run each module in the order it appears in the configuration
	for _, modconf := range conf.Modules {
		if *runmod != "all" && *runmod != modconf.Name {
			continue
		}
		if _, ok := modules.Available[modconf.Name]; !ok {
			log.Printf("[warning] %s module not registered, skipping it", modconf.Name)
			continue
		}
		// one-off reset uses the first module config, skips subsequent
		if *resetUsers != "" {
			if _, ok := moduleHasRun[modconf.Name]; ok {
				log.Printf("[warning] SKIPPING duplicate module config %s! Reset uses only the FIRST configuration for a given module.", modconf.Name)
				continue
			}
		}
		log.Println("[info] invoking module", modconf.Name)
		run := modules.Available[modconf.Name].NewRun(modconf)
		err = run.Run()
		if err != nil {
			log.Printf("[error] %s module failed with error: %v", modconf.Name, err)
		}
		moduleHasRun[modconf.Name] = true
	}
	// Modules are done, close the notification channel to tell the goroutine
	// that it can aggregate and send them, and wait for notifdone to come back
	close(notifchan)
	<-notifdone
}
