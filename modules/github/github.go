// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Miles Crabill <mcrabill@mozilla.com>

package github

import (
	"log"
	"strings"

	"github.com/google/go-github/github"
	"go.mozilla.org/userplex/modules"
	"golang.org/x/oauth2"
)

func init() {
	modules.Register("github", new(module))
}

type module struct{}

func (m *module) NewRun(c modules.Configuration) modules.Runner {
	r := new(run)
	r.Conf = c
	return r
}

type run struct {
	Conf     modules.Configuration
	p        parameters
	c        credentials
	ghclient *github.Client
}

type organization struct {
	Name  string
	Teams []string
}

type parameters struct {
	Organizations []organization
}

type credentials struct {
	oauthToken string
}

func (r *run) Run() error {
	var resp *github.Response

	err := r.Conf.GetParameters(&r.p)
	if err != nil {
		return err
	}
	err = r.Conf.GetCredentials(&r.c)
	if err != nil {
		return err
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: r.c.oauthToken},
	)
	tc := oauth2.NewClient(oauth2.NoContext, ts)
	r.ghclient = github.NewClient(tc)

	ldapers := r.getLdapers()

	for _, org := range r.p.Organizations {
		// get all teams for the organization
		// name -> team
		teamsMap := r.getTeamsMap(org)

		// get all members for the organization
		// name -> bool
		membersMap := r.getMembersMap(org)

		// member or admin
		membershipType := "member"

		for user := range ldapers {
			// set to true to indicate that user in github has ldap match
			membersMap[user] = true
			if user != "milescrabill" {
				continue
			}
			// if the user's ldap account is in the organization already
			if _, ok := membersMap[user]; ok {
				if r.Conf.Debug {
					log.Printf("[debug] github: user %s is already a member of organization %s", user, org)
				}
			}
			if r.Conf.ApplyChanges && r.Conf.Create {
				for _, teamName := range org.Teams {
					// if the team in config exists on github
					if team, ok := teamsMap[teamName]; ok {
						// add user to team
						_, resp, err = r.ghclient.Organizations.AddTeamMembership(*team.ID, user, &github.OrganizationAddTeamMembershipOptions{
							Role: membershipType,
						})
						if err != nil || resp.StatusCode != 200 {
							log.Printf("[error] github: could not add user %s to %s: %s, error: %v with status %s", user, org.Name, *team.Name, err, resp.Status)
						}
					} else {
						log.Printf("[error] github: could not find team %s for organization %s", team, org.Name)
					}
				}
			}
		}
		for user, inLdap := range membersMap {
			// users who exists in github org but not in ldap
			if !inLdap {
				log.Printf("[info] user %v is not in ldap groups %v but is a member of github organization %s", user, r.Conf.LdapGroups, org.Name)
				// TODO: not realistic to enable ever
				if r.Conf.ApplyChanges && r.Conf.Delete && 1 == 0 {
					resp, err = r.ghclient.Organizations.RemoveOrgMembership(org.Name, user)
					if err != nil || resp.StatusCode != 200 {
						log.Printf("[error] github: could not remove user %s from %s, error: %v with status %s", user, org.Name, err, resp.Status)
					}
				}
			}
		}
	}
	return nil
}

func (r *run) getMembersMap(org organization) map[string]bool {
	members, resp, err := r.ghclient.Organizations.ListMembers(org.Name, nil)
	if err != nil || resp.StatusCode != 200 {
		log.Printf("[error] github: could not list members for organization %s, error: %v with status %s", org, err, resp.Status)
	}
	membersMap := make(map[string]bool)
	for _, member := range members {
		membersMap[*member.Login] = false
	}
	return membersMap
}

func (r *run) getTeamsMap(org organization) map[string]*github.Team {
	teamsMap := make(map[string]*github.Team)
	teams, resp, err := r.ghclient.Organizations.ListTeams(org.Name, nil)
	if err != nil || resp.StatusCode != 200 {
		log.Printf("[error] github: could not list teams for organization %s, error: %v", org.Name, err)
	}
	for _, team := range teams {
		teamsMap[*team.Name] = team
	}
	return teamsMap
}

func (r *run) getLdapers() (lgm map[string]bool) {
	lgm = make(map[string]bool)
	users, err := r.Conf.LdapCli.GetEnabledUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		return
	}
	for _, user := range users {
		shortdn := strings.Split(user, ",")[0]
		uid, err := r.Conf.LdapCli.GetUserId(shortdn)
		if err != nil {
			log.Printf("[error] github: ldap query failed with error %v", err)
			continue
		}
		// apply the uid map: only store the translated uid in the ldapuid
		for _, mapping := range r.Conf.UidMap {
			if mapping.LdapUid == uid {
				uid = mapping.LocalUID
			}
		}
		lgm[uid] = true
	}
	return
}
