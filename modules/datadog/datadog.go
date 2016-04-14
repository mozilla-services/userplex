// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package datadog

import (
	"fmt"
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
	dcli *datadog.Client
}

type parameters struct {
}

type credentials struct {
	ApiKey string
	AppKey string
}

func (r *run) Run() (err error) {
	err = r.Conf.GetParameters(&r.p)
	if err != nil {
		return
	}
	err = r.Conf.GetCredentials(&r.c)
	if err != nil {
		return
	}
	r.dcli = datadog.NewClient(r.c.ApiKey, r.c.AppKey)

	ldapmails, err := r.findLdapUsers()
	if err != nil {
		return
	}
	ddusers, err := r.dcli.GetUsers()
	if err != nil {
		return
	}
	// find users to invite by comparing the ldap list with the existing datadog users
	if r.Conf.Create {
		err = r.create(ldapmails, ddusers)
		if err != nil {
			return
		}
	}

	// find datadog users that are no longer in ldap and need to be disabled
	if r.Conf.Delete {
		err = r.delete(ldapmails, ddusers)
		if err != nil {
			return
		}
	}
	return
}

func (r *run) findLdapUsers() (ldapmails []string, err error) {
	userdns, err := r.Conf.LdapCli.GetEnabledUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		return
	}
	for _, user := range userdns {
		shortdn := strings.Split(user, ",")[0]
		mail, err := r.Conf.LdapCli.GetUserEmail(shortdn)
		if err != nil {
			log.Printf("[error] can't get email of user %q: %v", shortdn, err)
			continue
		}
		// apply the uid map: only store the translated uid in the ldapuid
		for _, mapping := range r.Conf.UidMap {
			if mapping.LdapUid == mail {
				mail = mapping.LocalUID
			}
		}
		ldapmails = append(ldapmails, mail)
	}
	return
}

func (r *run) create(ldapmails []string, ddusers []datadog.User) (err error) {
	var newusers []string
	for _, ldapmail := range ldapmails {
		found := false
		for _, dduser := range ddusers {
			if ldapmail == dduser.Handle {
				found = true
				break
			}
		}
		if !found {
			log.Printf("[info] user %q was not found in datadog. needs inviting.", ldapmail)
			newusers = append(newusers, ldapmail)
			// notify user
			rcpt := r.Conf.Notify.Recipient
			if rcpt == "{ldap:mail}" {
				rcpt = ldapmail
			}
			r.Conf.Notify.Channel <- modules.Notification{
				Module:      "datadog",
				Recipient:   rcpt,
				Mode:        "smtp",
				Body:        []byte(fmt.Sprintf(`User %s has been invited to join Datadog.`, ldapmail)),
				MustEncrypt: false,
			}
		}
	}
	if r.Conf.DryRun {
		log.Printf("[dryrun] would have invited %d users to datadog", len(newusers))
	} else {
		err = r.dcli.InviteUsers(newusers)
		if err != nil {
			log.Printf("[error] failed to invite datadog users: %v", err)
		}
	}
	return
}

func (r *run) delete(ldapmails []string, ddusers []datadog.User) (err error) {
	for _, dduser := range ddusers {
		if dduser.Disabled {
			continue
		}
		found := false
		for _, ldapmail := range ldapmails {
			if dduser.Handle == ldapmail {
				found = true
				break
			}
		}
		if !found {
			if r.Conf.DryRun {
				log.Printf("[dryrun] would have disabled user %q from datadog", dduser.Handle)
				goto notify
			}
			dduser.Disabled = true
			err = r.dcli.UpdateUser(dduser)
			if err != nil {
				log.Printf("[error] failed to disabled datadog user %q: %v", dduser.Handle)
			}
		notify:
			// notify user
			rcpt := r.Conf.Notify.Recipient
			if rcpt == "{ldap:mail}" {
				rcpt = dduser.Handle
			}
			r.Conf.Notify.Channel <- modules.Notification{
				Module:      "datadog",
				Recipient:   rcpt,
				Mode:        r.Conf.Notify.Mode,
				Body:        []byte(fmt.Sprintf(`User %s has been removed from Datadog.`, dduser.Handle)),
				MustEncrypt: false,
			}

		}
	}
	return
}
