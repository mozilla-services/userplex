// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Miles Crabill <mcrabill@mozilla.com>

package pagerduty

import (
	"fmt"
	"log"
	"strings"

	pagerduty "github.com/PagerDuty/go-pagerduty"

	"go.mozilla.org/userplex/modules"
)

func init() {
	modules.Register("pagerduty", new(module))
}

type module struct{}

func (m *module) NewRun(c modules.Configuration) modules.Runner {
	r := new(run)
	r.Conf = c
	return r
}

type run struct {
	Conf modules.Configuration
	p    parameters
	c    credentials

	pagerdutyEmailToLdapEmail  map[string]string
	ldapEmailToPagerdutyEmails map[string][]string
}

type parameters struct {
	Subdomain string
}

type credentials struct {
	APIKey string
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

	r.buildLdapMapping()
	ldapers := r.getLdaperEmails()

	client := pagerduty.NewClient(r.c.APIKey)

	var allUsers []pagerduty.User
	offset := uint(0)
	opt := pagerduty.ListUserOptions{
		APIListObject: pagerduty.APIListObject{Offset: offset},
	}
	for {
		usersResp, err := client.ListUsers(opt)
		if err != nil {
			log.Fatalf("[error] pagerduty %s: %s", r.p.Subdomain, err.Error())
		}
		allUsers = append(allUsers, usersResp.Users...)
		if !usersResp.More {
			break
		}
		offset += usersResp.Limit
		opt.APIListObject.Offset = offset
	}

	log.Printf("[info] pagerduty %s: found %d users", r.p.Subdomain, len(allUsers))

	// all pagerduty users
	for _, user := range allUsers {
		// if there's an ldapuid/localuid mapping for the user
		var ldapEmail, ldapEmailString string
		if email, ok := r.pagerdutyEmailToLdapEmail[user.Email]; ok {
			ldapEmail = email
			ldapEmailString = " (pagerduty) / " + ldapEmail + " (ldap)"
		}
		if ldapEmail == "" {
			ldapEmail = user.Email
		}

		// if the user is in ldap
		if _, ok := ldapers[ldapEmail]; ok {
			ldapers[ldapEmail] = true
		} else {
			// user not in ldap
			log.Printf("[info] pagerduty %s: user %s%s is not in ldap groups %s but is in PagerDuty account %s", r.p.Subdomain, user.Email, ldapEmailString, r.Conf.LdapGroups, r.p.Subdomain)
			if r.Conf.Delete {
				if !r.Conf.ApplyChanges {
					log.Printf("[dryrun] pagerduty %s: would have deleted user %s", r.p.Subdomain, user.Email)
				} else {
					err := client.DeleteUser(user.ID)
					if err != nil {
						log.Fatalf("[error] pagerduty %s: could not delete user %s: %s", r.p.Subdomain, user.Email, err.Error())
					}
				}
				r.notify(ldapEmail, fmt.Sprintf("Userplex deleted %s from Pagerduty account %s", ldapEmail, r.p.Subdomain))
			}
		}
	}

	for ldapEmail, isInPagerduty := range ldapers {
		// if there's an ldapuid/localuid mapping for the user
		var (
			pagerdutyEmails       []string
			pagerdutyEmailsString string
		)
		if emails, ok := r.ldapEmailToPagerdutyEmails[ldapEmail]; ok {
			pagerdutyEmails = emails
			pagerdutyEmailsString = strings.Join(pagerdutyEmails, ", ") + " (pagerduty) / "
		}

		if !isInPagerduty && r.Conf.Create {
			log.Printf("[info] pagerduty %s: user %s%s (ldap) is not in Pagerduty account %s", r.p.Subdomain, pagerdutyEmailsString, ldapEmail, r.p.Subdomain)
			if !r.Conf.ApplyChanges {
				log.Printf("[dryrun] pagerduty %s: would have created user %s", r.p.Subdomain, ldapEmail)
			} else {
				// add user to pagerduty
				client.CreateUser(pagerduty.User{
					Email: ldapEmail,
					Name:  ldapEmail,
				})
			}
			r.notify(ldapEmail, fmt.Sprintf("Userplex added %s to Pagerduty account %s", ldapEmail, r.p.Subdomain))
		}
	}

	return
}

func (r *run) buildLdapMapping() {
	r.pagerdutyEmailToLdapEmail = make(map[string]string)
	r.ldapEmailToPagerdutyEmails = make(map[string][]string)
	for _, mapping := range r.Conf.UidMap {
		r.pagerdutyEmailToLdapEmail[mapping.LocalUID] = mapping.LdapUid
		r.ldapEmailToPagerdutyEmails[mapping.LdapUid] = append(r.ldapEmailToPagerdutyEmails[mapping.LdapUid], mapping.LocalUID)
	}
}

func (r *run) getLdaperEmails() (ldapUsers map[string]bool) {
	ldapUsers = make(map[string]bool)
	users, err := r.Conf.LdapCli.GetEnabledUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		return
	}
	for _, user := range users {
		shortdn := strings.Split(user, ",")[0]
		userEmail, err := r.Conf.LdapCli.GetUserEmail(shortdn)
		if err != nil {
			log.Printf("[error] pagerduty: could not get email for user %s: %v", shortdn, err)
			continue
		}

		ldapUsers[userEmail] = false
	}
	return
}

func (r *run) notify(ldapEmail string, body string) (err error) {
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		// if email, ok := r.pagerdutyEmailToLdapEmail[ldapEmail]; ok {
		// 	ldapEmail = email
		// }
		rcpt = ldapEmail
	}
	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "github",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: false,
		Body:        []byte(body),
	}
	return
}
