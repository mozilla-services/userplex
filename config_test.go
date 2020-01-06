package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := loadConf("config.yaml")

	assert.NoError(t, err)
	assert.Equal(t, "client_id", cfg.Person.PersonClientId)
	assert.Equal(t, "myawsaccount", cfg.Aws[0].AccountName)
	assert.Len(t, cfg.AuthorizedKeys, 2)
}
