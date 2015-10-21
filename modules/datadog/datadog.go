// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>
package aws

import (
	"log"
	"strings"

	"github.com/mozilla-services/userplex/modules"
	"github.com/zorkian/go-datadog-api"
)

func init() {
	modules.Register("datadog", new(module))
}

type module struct {
}

func (m *module) NewRun(c modules.Configuration) modules.Runner {
	r := new(run)
	r.Conf = c
	return r
}

type run struct {
	Conf modules.Configuration
	p    parameters
	c    credentials
}

type parameters struct {
}

type credentials struct {
	ApiKey string
	AppKey string
}

func (r *run) Run() (err error) {
	var (
		params parameters
		creds  credentials
	)
	err = r.Conf.GetParameters(&params)
	if err != nil {
		return
	}
	r.p = params
	err = r.Conf.GetCredentials(&creds)
	if err != nil {
		return
	}
	r.c = creds
	client := datadog.NewClient(r.c.ApiKey, r.c.AppKey)

	users, err := r.Conf.LdapCli.GetUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		return
	}
	var usermails []string
	for _, user := range users {
		shortdn := strings.Split(user, ",")[0]
		mail, err := r.Conf.LdapCli.GetUserEmail(shortdn)
		if err != nil {
			log.Printf("[error] can't get email of user %q: %v", shortdn, err)
			continue
		}
		usermails = append(usermails, mail)
	}
	if r.Conf.DryRun {
		log.Printf("[dryrun] would have invited %d users to join datadog", len(usermails))
		return
	}

	//FIXME: exiting here because datadog is stoopid and will send notifications
	// to all users all the time
	return

	err = client.InviteUsers(usermails)
	if err != nil {
		log.Printf("[error] failed to invite datadog users: %v", err)
	}
	for _, mail := range usermails {
		log.Printf("[info] invited user %q to join datadog", mail)
	}
	return
}
