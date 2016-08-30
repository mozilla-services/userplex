package main

import (
	"io/ioutil"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"

	"go.mozilla.org/mozldap"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/aes"
	sopsyaml "go.mozilla.org/sops/yaml"
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
	var data []byte
	// read configuration from stdin if no config file was
	// passed in command line arguments
	if *config == "" {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(*config)
	}
	if err != nil {
		return
	}
	// try to decrypt the conf using sops or load it as plaintext
	// if it's not encrypted
	decryptedConf, err := decryptConf(data)
	if err != nil {
		// decryption would have failed if the file is not encrypted,
		// in which case simply continue loading as yaml. But if the
		// file is encrypted and decryption failed, exit here.
		if err != sops.MetadataNotFound {
			return
		}
	} else {
		data = decryptedConf
	}
	err = yaml.Unmarshal(data, &cfg)
	return
}

func decryptConf(encryptedConf []byte) (decryptedConf []byte, err error) {
	store := &sopsyaml.Store{}
	metadata, err := store.UnmarshalMetadata(encryptedConf)
	if err != nil {
		return
	}
	key, err := metadata.GetDataKey()
	if err != nil {
		return
	}
	branch, err := store.Unmarshal(encryptedConf)
	if err != nil {
		return
	}
	tree := sops.Tree{Branch: branch, Metadata: metadata}
	cipher := aes.Cipher{}
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return
	}
	originalMac, err := cipher.Decrypt(
		metadata.MessageAuthenticationCode,
		key,
		[]byte(metadata.LastModified.Format(time.RFC3339)),
	)
	if originalMac != mac {
		return
	}
	return store.Marshal(tree.Branch)
}
