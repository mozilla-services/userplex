package modules

import (
	"github.com/mozilla-services/mozldap"
	"gopkg.in/yaml.v2"
)

// Configuration holds module specific parameters
type Configuration struct {
	Name        string         `yaml:"name",json:"name"`
	LdapGroups  []string       `yaml:"ldapgroups",json:"ldapgroups"`
	Create      bool           `yaml:"create",json:"create"`
	Delete      bool           `yaml:"delete",json:"delete"`
	Credentials interface{}    `yaml:"credentials",json:"credentials"`
	Parameters  interface{}    `yaml:"parameters",json:"parameters"`
	DryRun      bool           `yaml:"dryrun",json:"dryrun"`
	LdapCli     mozldap.Client `yaml:"-",json:"-"`
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
