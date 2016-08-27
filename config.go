package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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

const (
	errNotSopsFormat string = "sops metadata not found in input data"
	errInvalidMac    string = "failed to verify the integrity of the sops file (MAC mismatch)"
)

func loadConf(path string) (cfg conf, err error) {
	var data []byte
	if *config == "" {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(*config)
	}
	if err != nil {
		return
	}
	// try to decrypt the conf
	decryptedConf, err := decryptConf(data)
	if err != nil {
		// decryption would have failed if the file is not encrypted,
		// in which case simply continue loading as yaml. But if the
		// file is encrypted and decryption failed, exit here.
		if !strings.Contains(err.Error(), errNotSopsFormat) {
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
	metadata, err := store.LoadMetadata(string(encryptedConf))
	if err != nil {
		err = fmt.Errorf("%s: %v", errNotSopsFormat, err)
		return
	}
	key, err := findKey(metadata.KeySources)
	if err != nil {
		return
	}
	branch, err := store.Load(string(encryptedConf))
	if err != nil {
		return
	}
	tree := sops.Tree{Branch: branch, Metadata: metadata}
	cipher := aes.Cipher{}
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return
	}
	originalMac, err := cipher.Decrypt(metadata.MessageAuthenticationCode, key, []byte(metadata.LastModified.Format(time.RFC3339)))
	if originalMac != mac {
		err = fmt.Errorf("%s", errInvalidMac)
		return
	}
	out, err := store.Dump(tree.Branch)
	if err != nil {
		return
	}
	return []byte(out), nil
}

func findKey(keysources []sops.KeySource) ([]byte, error) {
	for _, ks := range keysources {
		for _, k := range ks.Keys {
			key, err := k.Decrypt()
			if err == nil {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("Could not get master key")
}
