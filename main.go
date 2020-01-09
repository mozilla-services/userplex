package main

import (
	"fmt"
	"os"
	"strings"

	"go.mozilla.org/person-api"
	"go.mozilla.org/userplex/modules"
	"go.mozilla.org/userplex/modules/authorizedkeys"
	"go.mozilla.org/userplex/modules/aws"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const Version = "v1.0.0"

func main() {
	app := cli.NewApp()
	app.Name = "userplex"
	app.Usage = "Propagate users from Mozilla's Person API to third party systems."
	app.Version = Version
	app.Authors = []cli.Author{
		{Name: "AJ Bahnken", Email: "ajvb@mozilla.com"},
		{Name: "Julien Vehent", Email: "jvehent@mozilla.com"},
	}
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config, c",
			Usage:  "Path to userplex config file",
			EnvVar: "USERPLEX_CONFIG_PATH",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:        "aws",
			Usage:       "Operations within AWS",
			Action:      requiresSubcommand,
			Subcommands: createModuleSubcommands(&aws.AWSModule{}),
		},
		{
			Name:        "authorizedkeys",
			Usage:       "Operations within authorizedkeys files",
			Action:      requiresSubcommand,
			Subcommands: createModuleSubcommands(&authorizedkeys.AuthorizedKeysModule{}),
		},
		{
			Name:      "get-person",
			Usage:     "Get Person from Person API. Useful for finding the correct identifier",
			ArgsUsage: "[user-identifier]",
			Action:    getPersonCmd,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func requiresSubcommand(c *cli.Context) error {
	log.Error("You must specify a subcommand")
	return nil
}

func createModuleSubcommands(module modules.Module) []cli.Command {
	return []cli.Command{
		{
			Name:      "create",
			Usage:     "Create user",
			ArgsUsage: "[username]",
			Action: func(c *cli.Context) error {
				person, conf, moduleConfs, personClient := loadAndVerifyContext(c, module, true)
				for _, mconf := range moduleConfs {
					m := module.NewFromInterface(mconf, conf.Notifications, personClient)
					err := m.Create(person.GetLDAPUsername(), person)
					if err != nil {
						log.Errorf("Error from module.Create: %s", err)
						return err
					}
				}
				return nil
			},
		},
		{
			Name:      "reset",
			Usage:     "Reset user credentials",
			ArgsUsage: "[username]",
			Action: func(c *cli.Context) error {
				person, conf, moduleConfs, personClient := loadAndVerifyContext(c, module, true)
				for _, mconf := range moduleConfs {
					m := module.NewFromInterface(mconf, conf.Notifications, personClient)
					err := m.Reset(person.GetLDAPUsername(), person)
					if err != nil {
						log.Errorf("Error from module.Reset: %s", err)
						return err
					}
				}
				return nil
			},
		},
		{
			Name:      "delete",
			Usage:     "Delete user",
			ArgsUsage: "[username]",
			Action: func(c *cli.Context) error {
				person, conf, moduleConfs, personClient := loadAndVerifyContext(c, module, false)
				for _, mconf := range moduleConfs {
					m := module.NewFromInterface(mconf, conf.Notifications, personClient)
					var err error
					if person != nil {
						err = m.Delete(person.GetLDAPUsername())
					} else {
						err = m.Delete(c.Args()[0])
					}
					if err != nil {
						log.Errorf("Error from module.Delete: %s", err)
						return err
					}
				}
				return nil
			},
		},
		{
			Name:  "sync",
			Usage: "Run sync operation",
			Action: func(c *cli.Context) error {
				conf, moduleConfs, personClient := loadConfigForSubcommand(c, module)
				for _, mconf := range moduleConfs {
					m := module.NewFromInterface(mconf, conf.Notifications, personClient)
					err := m.Sync()
					if err != nil {
						log.Errorf("Error from module.Sync: %s", err)
						return err
					}
				}
				return nil
			},
		},
		{
			Name:  "verify",
			Usage: "Verify users against Person API. Outputs report, use `sync` to fix discrepancies.",
			Action: func(c *cli.Context) error {
				conf, moduleConfs, personClient := loadConfigForSubcommand(c, module)
				for _, mconf := range moduleConfs {
					m := module.NewFromInterface(mconf, conf.Notifications, personClient)
					err := m.Verify()
					if err != nil {
						log.Errorf("Error from module.Verify: %s", err)
						return err
					}
				}
				return nil
			},
		},
	}
}

func loadConfigForSubcommand(c *cli.Context, module modules.Module) (conf, []modules.Configuration, *person_api.Client) {
	cfg, err := loadConf(c.GlobalString("c"))
	if err != nil {
		log.Fatalf("Couldn't load config: %s", err)
	}

	personClient, err := person_api.NewClient(
		cfg.Person.PersonClientId,
		cfg.Person.PersonClientSecret,
		cfg.Person.PersonBaseURL,
		cfg.Person.PersonAuth0URL,
	)
	if err != nil {
		log.Fatalf("Could not create person api client: %s", err)
	}

	var moduleConfigs []modules.Configuration
	switch module {
	case module.(*aws.AWSModule):
		moduleConfigs = make([]modules.Configuration, len(cfg.Aws))
		for i, c := range cfg.Aws {
			moduleConfigs[i] = c
		}
	case module.(*authorizedkeys.AuthorizedKeysModule):
		moduleConfigs = make([]modules.Configuration, len(cfg.AuthorizedKeys))
		for i, c := range cfg.AuthorizedKeys {
			moduleConfigs[i] = c
		}
	}

	return cfg, moduleConfigs, personClient
}

func loadAndVerifyContext(c *cli.Context, module modules.Module, exitOnError bool) (*person_api.Person, conf, []modules.Configuration, *person_api.Client) {
	cfg, moduleConfigs, personClient := loadConfigForSubcommand(c, module)
	username := c.Args()[0]

	p, err := getPerson(personClient, username)
	if err != nil {
		if exitOnError {
			log.Fatalf("Could not find user %s", username)
		}
	}

	if p != nil && len(p.GetSSHPublicKeys()) == 0 {
		if exitOnError {
			log.Fatalf("User %s has no SSH public keys. A SSH public key must be added before userplex can be ran.", username)
		}
	}
	if p != nil && len(p.GetPGPPublicKeys()) == 0 {
		if exitOnError {
			log.Fatalf("User %s has no PGP public keys. A PGP public key must be added before userplex can be ran.", username)
		}
	}

	if len(moduleConfigs) == 0 {
		log.Fatalf("No module configurations found for %s", module)
	}

	return p, cfg, moduleConfigs, personClient
}

func getPersonCmd(c *cli.Context) error {
	cfg, err := loadConf(c.GlobalString("c"))
	if err != nil {
		log.Fatalf("Couldn't load config: %s", err)
	}

	personClient, err := person_api.NewClient(
		cfg.Person.PersonClientId,
		cfg.Person.PersonClientSecret,
		cfg.Person.PersonBaseURL,
		cfg.Person.PersonAuth0URL,
	)
	if err != nil {
		log.Fatalf("Could not create person api client: %s", err)
	}
	username := c.Args()[0]

	p, err := getPerson(personClient, username)
	if err != nil {
		log.Fatalf("Could not find user %s", username)
	}

	if p.PrimaryEmail.Value == "" {
		log.Fatalf("Could not find user %s", username)
	}

	log.Infof("%s: %+v", p.GetLDAPUsername(), p)
	return nil
}

func getPerson(personClient *person_api.Client, username string) (*person_api.Person, error) {
	var (
		p   *person_api.Person
		err error
	)

	if strings.Contains(username, "@mozilla.com") {
		p, err = personClient.GetPersonByEmail(username)
		if err != nil {
			return nil, fmt.Errorf("Could not find user %s: %s", username, err)
		}
	} else {
		p, err = personClient.GetPersonByUsername(username)
		if err != nil || p.PrimaryEmail.Value == "" {
			p, err = personClient.GetPersonByUserId(username)
			if err != nil {
				return nil, fmt.Errorf("Could not find user %s: %s", username, err)
			}
		}
	}
	if p.PrimaryEmail.Value == "" {
		return nil, fmt.Errorf("Could not find user %s", username)
	}
	return p, err
}
