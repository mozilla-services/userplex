package main

import (
	"io/ioutil"

	"go.mozilla.org/userplex/modules"
	"go.mozilla.org/userplex/notifications"

	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

type conf struct {
	Person struct {
		PersonClientId     string `yaml:"person_client_id"`
		PersonClientSecret string `yaml:"person_client_secret"`
		PersonBaseURL      string `yaml:"person_base_url"`
		PersonAuth0URL     string `yaml:"person_auth0_url"`
	} `yaml:"person"`

	Notifications notifications.Config `yaml:"notifications"`

	UsernameMap []modules.Umap `yaml:"username_map" json:"username_map"`

	Aws []modules.AWSConfiguration `yaml:"aws"`

	AuthorizedKeys []modules.AuthorizedKeysConfiguration `yaml:"authorized_keys"`
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
