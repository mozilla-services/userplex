package main

import (
	"io/ioutil"

	"github.com/pkg/errors"
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
		cli                     mozldap.Client
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
	var confData []byte
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err = decrypt.Data(data, "yaml")
	if err != nil {
		if err == sops.MetadataNotFound {
			// not an encrypted file
			confData = data
		} else {
			return cfg, errors.Wrap(err, "failed to load sops encrypted configuration")
		}
	}
	err = yaml.Unmarshal(confData, &cfg)
	return
}
