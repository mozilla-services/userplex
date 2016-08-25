// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Miles Crabill <mcrabill@mozilla.com>

package github

import (
	"fmt"
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
	Organizations    []organization
	UserplexTeamName string
}

type credentials struct {
	OAuthToken string `yaml:"oauthtoken"`
}

func (r *run) Run() (err error) {
	var resp *github.Response

	err = r.Conf.GetParameters(&r.p)
	if err != nil {
		return
	}
	err = r.Conf.GetCredentials(&r.c)
	if err != nil {
		return
	}

	if r.p.UserplexTeamName == "" {
		return fmt.Errorf("[error] github: UserplexTeamName is not set")
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: r.c.OAuthToken},
	)
	tc := oauth2.NewClient(oauth2.NoContext, ts)
	r.ghclient = github.NewClient(tc)

	ldapers := r.getLdapers()

	for _, org := range r.p.Organizations {
		// get all teams for the organization
		// name -> team
		teamsMap := r.getOrgTeamsMap(org)

		if _, ok := teamsMap[r.p.UserplexTeamName]; !ok {
			log.Printf("[error] github: could not find Userplex team %s for organization %s", r.p.UserplexTeamName, org.Name)
			continue
		}

		var userplexedUsers map[string]bool
		if _, ok := teamsMap[r.p.UserplexTeamName]; ok {
			userplexedUsers = r.getTeamMembersMap(teamsMap[r.p.UserplexTeamName])
		}

		// get all members for the organization
		// name -> bool
		membersMap := r.getOrgMembersMap(org)

		// member or admin
		membershipType := "member"

		for user := range ldapers {
			// set to true to indicate that user in github has ldap match
			membersMap[user] = true
			if user != "milescrabill" && user != "mcrabill" {
				continue
			}

			// not managed by userplex
			if _, ok := userplexedUsers[user]; !ok {
				continue
			}

			// if the user is in the organization already
			if _, ok := membersMap[user]; ok {
				if r.Conf.Debug {
					log.Printf("[debug] github: user %s is already a member of organization %s", user, org)
				}
				// check whether the user is in each team
				shouldContinue := true
				for _, team := range teamsMap {
					var isInTeam bool
					isInTeam, resp, err = r.ghclient.Organizations.IsTeamMember(*team.ID, user)
					if !isInTeam {
						shouldContinue = false
					}
				}
				if shouldContinue {
					continue
				}
			}
			for _, teamName := range org.Teams {
				// if the team in config exists on github
				if team, ok := teamsMap[teamName]; ok {
					if r.Conf.ApplyChanges && r.Conf.Create {
						// add user to team
						_, resp, err = r.ghclient.Organizations.AddTeamMembership(*team.ID, user, &github.OrganizationAddTeamMembershipOptions{
							Role: membershipType,
						})
						if err != nil || resp.StatusCode != 200 {
							log.Printf("[error] github: could not add user %s to %s: %s, error: %v with status %s", user, org.Name, *team.Name, err, resp.Status)
						}
					}
				} else {
					log.Printf("[error] github: could not find team %s for organization %s", team, org.Name)
				}
			}
			if !r.Conf.ApplyChanges {
				log.Printf("[dryrun] Userplex would have added %s to GitHub organization %s and teams %v", user, org.Name, org.Teams)
			} else {
				r.notify(user, fmt.Sprintf("Userplex added %s to GitHub organization %s and teams %v", user, org.Name, org.Teams))
			}
		}
		for user := range membersMap {
			// userplexed users not in ldap
			_, isUserplexed := userplexedUsers[user]
			if !membersMap[user] && isUserplexed {
				log.Printf("[info] user %v is not in ldap groups %v but is a member of github organization %s", user, r.Conf.LdapGroups, org.Name)
				if !r.Conf.ApplyChanges {
					log.Printf("[dryrun] Userplex would have removed %s from GitHub organization %s", user, org.Name)
				} else {
					r.notify(user, fmt.Sprintf("Userplex removed %s to GitHub organization %s", user, org.Name))
				}
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

func (r *run) notify(user string, body string) (err error) {
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		// reverse the uid map
		for _, mapping := range r.Conf.UidMap {
			if mapping.LocalUID == user {
				user = mapping.LdapUid
			}
		}
		rcpt, err = r.Conf.LdapCli.GetUserEmailByUid(user)
		if err != nil {
			log.Printf("[error] github: couldn't find email of user %q in ldap, notification not sent: %v", user, err)
			return
		}
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

func (r *run) getOrgMembersMap(org organization) map[string]bool {
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

func (r *run) getTeamMembersMap(team *github.Team) map[string]bool {
	members, resp, err := r.ghclient.Organizations.ListTeamMembers(*team.ID, nil)
	if err != nil || resp.StatusCode != 200 {
		log.Printf("[error] github: could not list members for organization %s, error: %v with status %s", team, err, resp.Status)
	}
	membersMap := make(map[string]bool)
	for _, member := range members {
		membersMap[*member.Login] = false
	}
	return membersMap
}

func (r *run) getOrgTeamsMap(org organization) map[string]*github.Team {
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
		lgm[uid] = false
	}
	return
}
