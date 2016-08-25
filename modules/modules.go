// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package modules // import "go.mozilla.org/userplex/modules"

import (
	"go.mozilla.org/mozldap"
	"gopkg.in/yaml.v2"
)

// Configuration holds module specific parameters
type Configuration struct {
	Name           string         `yaml:"name" json:"name"`
	LdapGroups     []string       `yaml:"ldapgroups" json:"ldapgroups"`
	UidMap         []umap         `yaml:"uidmap" json:"uidmap"`
	Create         bool           `yaml:"create" json:"create"`
	Delete         bool           `yaml:"delete" json:"delete"`
	Reset          bool           `yaml:"reset" json:"reset"`
	ResetUsername  string         `yaml:"resetusername" json:"resetusername"`
	CreateUsername string         `yaml:"createusername" json:"resetusername"`
	DeleteUsername string         `yaml:"deleteusername" json:"resetusername"`
	Notify         NotifyConf     `yaml:"notify" json:"notify"`
	Credentials    interface{}    `yaml:"credentials" json:"credentials"`
	Parameters     interface{}    `yaml:"parameters" json:"parameters"`
	ApplyChanges   bool           `yaml:"applychanges" json:"applychanges"`
	NotifyUsers    bool           `yaml:"notifyusers" json:"notifyusers"`
	LdapCli        mozldap.Client `yaml:"-" json:"-"`
	Debug          bool           `yaml:"-" json:"-"`
}

type NotifyConf struct {
	Mode      string            `yaml:"mode" json:"mode"`
	Recipient string            `yaml:"recipient" json:"recipient"`
	Channel   chan Notification `yaml:"-" json:"-"`
}

type Notification struct {
	Module      string
	Recipient   string
	Mode        string
	Body        []byte
	MustEncrypt bool
}

type umap struct {
	LdapUid  string `yaml:"ldapuid" json:"ldapuid"`
	LocalUID string `yaml:"localuid" json:"localuid"`
}

// A module implements this interface
type Moduler interface {
	NewRun(Configuration) Runner
}

// Runner provides the interface to an execution of a module
type Runner interface {
	Run() error
}

// The set of registered modules
var Available = make(map[string]Moduler)

// Register a new module as available
func Register(name string, mod Moduler) {
	if _, exist := Available[name]; exist {
		panic("Register: a module named " + name + " has already been registered.\nAre you trying to import the same module twice?")
	}
	Available[name] = mod
}

// GetParameters reads the parameters from a Configuration into the p interface
func (c Configuration) GetParameters(p interface{}) (err error) {
	buf, err := yaml.Marshal(c.Parameters)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(buf, p)
	return
}

// GetCredentials reads the credentials from a Configuration into the c interface
func (c Configuration) GetCredentials(cred interface{}) (err error) {
	buf, err := yaml.Marshal(c.Credentials)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(buf, cred)
	return
}
