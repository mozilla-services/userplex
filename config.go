package main

import (
	"io/ioutil"
	"log"

	yaml "gopkg.in/yaml.v2"

	"go.mozilla.org/mozldap"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"
	"go.mozilla.org/userplex/modules"
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

func loadConf(path string) (cfg conf, err error) {
	log.Println("Accessing configuration from", path)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err := decrypt.Data(data, "yaml")
	if err != nil {
		if err.Error() == sops.MetadataNotFound.Error() {
			// not an encrypted file
			confData = data
		} else {
			return
		}
	}
	err = yaml.Unmarshal(confData, &cfg)
	return
}
