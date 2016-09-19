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

	pd *pagerduty.Client

	pagerdutyEmailToLdapEmail map[string]string
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

	r.pd = pagerduty.NewClient(r.c.APIKey)

	allUsers := r.getPagerdutyUsers()

	countDeleted := 0
	// all pagerduty users
	for _, user := range allUsers {
		// if there's an ldapuid/localuid mapping for the user
		var ldapEmail, ldapEmailString string
		if email, ok := r.pagerdutyEmailToLdapEmail[user.Email]; ok {
			ldapEmail = email
			// if there is a mapping for this user, make a string that
			// shows both pagerduty email and ldap email
			ldapEmailString = " (pagerduty) / " + ldapEmail + " (ldap)"
		}
		// keep pagerduty email if no ldapuid/localuid mapping
		if ldapEmail == "" {
			ldapEmail = user.Email
		}

		// if the user is in the ldap groups
		if _, ok := ldapers[ldapEmail]; ok {
			ldapers[ldapEmail] = true
		} else {
			// user not in ldap groups
			if r.Conf.Debug {
				log.Printf("[info] pagerduty %q: user %s%s is not in ldap groups %v but is in PagerDuty account %q", r.p.Subdomain, user.Email, ldapEmailString, r.Conf.LdapGroups, r.p.Subdomain)
			}
			if r.Conf.Delete {
				if !r.Conf.ApplyChanges {
					log.Printf("[dryrun] pagerduty %q: would have deleted user %s%s", r.p.Subdomain, user.Email, ldapEmailString)
				} else {
					err = r.pd.DeleteUser(user.ID)
					if err != nil {
						return fmt.Errorf("[error] pagerduty %q: could not delete user %s%s: %s", r.p.Subdomain, user.Email, ldapEmailString, err.Error())
					}
					countDeleted++
				}
				r.notify(ldapEmail, fmt.Sprintf("Userplex deleted %q from Pagerduty account %q", ldapEmail, r.p.Subdomain))
			}
		}
	}

	countCreated := 0
	// ldap users in selected groups
	for ldapEmail, isInPagerduty := range ldapers {
		if !isInPagerduty && r.Conf.Create {
			if r.Conf.Debug {
				log.Printf("[info] pagerduty %q: user %q is not in Pagerduty account %q", r.p.Subdomain, ldapEmail, r.p.Subdomain)
			}
			if !r.Conf.ApplyChanges {
				log.Printf("[dryrun] pagerduty %q: would have created user %q", r.p.Subdomain, ldapEmail)
			} else {
				// add user to pagerduty
				err = r.createPagerdutyUser(ldapEmail)
				if err != nil {
					return fmt.Errorf("[error] pagerduty %q: could not create user %q: %s", r.p.Subdomain, ldapEmail, err.Error())
				}
				countCreated++
			}
			r.notify(ldapEmail, fmt.Sprintf("Userplex added %s to Pagerduty account %q", ldapEmail, r.p.Subdomain))
		}
	}

	log.Printf("[info] pagerduty %q: summary created=%d, deleted=%d",
		r.p.Subdomain, countCreated, countDeleted)

	return
}

func (r *run) createPagerdutyUser(ldapEmail string) error {
	fullName, err := r.Conf.LdapCli.GetUserFullNameByEmail(ldapEmail)
	if err != nil {
		log.Printf("[error] pagerduty %q: could not get name from LDAP for user %q: %s", r.p.Subdomain, ldapEmail, err.Error())
		// fallback to name being email
		fullName = ldapEmail
	}
	r.pd.CreateUser(pagerduty.User{
		Email: ldapEmail,
		Name:  fullName,
	})
	return err
}

func (r *run) buildLdapMapping() {
	r.pagerdutyEmailToLdapEmail = make(map[string]string)
	for _, mapping := range r.Conf.UidMap {
		r.pagerdutyEmailToLdapEmail[mapping.LocalUID] = mapping.LdapUid
	}
}

func (r *run) getLdaperName() (name string) {
	return
}

func (r *run) getPagerdutyUsers() []pagerduty.User {
	// paginated api, get all users
	var allUsers []pagerduty.User
	offset := uint(0)
	opt := pagerduty.ListUserOptions{
		APIListObject: pagerduty.APIListObject{Offset: offset},
	}
	for {
		usersResp, err := r.pd.ListUsers(opt)
		if err != nil {
			log.Printf("[error] pagerduty %q: %s", r.p.Subdomain, err.Error())
		}
		allUsers = append(allUsers, usersResp.Users...)
		if !usersResp.More {
			break
		}
		offset += usersResp.Limit
		opt.APIListObject.Offset = offset
	}
	if r.Conf.Debug {
		log.Printf("[debug] pagerduty %q: found %d users", r.p.Subdomain, len(allUsers))
	}
	return allUsers
}

func (r *run) getLdaperEmails() (ldapUsers map[string]bool) {
	ldapUsers = make(map[string]bool)
	users, err := r.Conf.LdapCli.GetEnabledUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		log.Printf("[error] pagerduty: could not get users in LDAP groups %v", r.Conf.LdapGroups)
	}
	for _, user := range users {
		shortdn := strings.Split(user, ",")[0]
		userEmail, err := r.Conf.LdapCli.GetUserEmail(shortdn)
		if err != nil {
			log.Printf("[error] pagerduty: could not get email for user %q: %v", shortdn, err)
			continue
		}

		ldapUsers[userEmail] = false
	}
	return
}

func (r *run) notify(ldapEmail string, body string) (err error) {
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		rcpt = ldapEmail
	}
	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "pagerduty",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: false,
		Body:        []byte(body),
	}
	return
}
