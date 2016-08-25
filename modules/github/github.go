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
		// get all members for the organization
		// name -> bool
		membersMap := r.getOrgMembersMap(org)

		// get all teams for the organization
		// name -> team
		teamsMap := r.getOrgTeamsMap(org)

		if _, ok := teamsMap[r.p.UserplexTeamName]; !ok {
			log.Printf("[error] github: could not find UserplexTeam \"%s\" for organization %s", r.p.UserplexTeamName, org.Name)
			continue
		}

		teamMembersMap := make(map[string]map[string]bool)
		for _, team := range teamsMap {
			teamMembersMap[*team.Name] = make(map[string]bool)
			teamMembersMap[*team.Name] = r.getTeamMembersMap(team)
		}

		userplexedUsers := teamMembersMap[r.p.UserplexTeamName]

		// member or admin
		membershipType := "member"

		for user := range ldapers {
			// set to true to indicate that user in github has ldap match
			membersMap[user] = true

			// not managed by userplex
			if _, ok := userplexedUsers[user]; !ok {
				continue
			}

			// teams in config
			for _, teamName := range org.Teams {
				// if the team in config doesn't exist on github
				if team, ok := teamsMap[teamName]; !ok {
					log.Printf("[error] github: could not find team %s for organization %s", team, org.Name)
				} else {
					// if the user is already in the team, skip adding them
					if _, ok := teamMembersMap[teamName][user]; ok {
						continue
					}
					// user not in team, add them
					if r.Conf.ApplyChanges && r.Conf.Create {
						// add user to team
						_, resp, err = r.ghclient.Organizations.AddTeamMembership(*team.ID, user, &github.OrganizationAddTeamMembershipOptions{
							Role: membershipType,
						})
						if err != nil || resp.StatusCode != 200 {
							log.Printf("[error] github: could not add user %s to %s: %s, error: %v with status %s", user, org.Name, *team.Name, err, resp.Status)
						}
					}
				}
			}
			if !r.Conf.ApplyChanges && r.Conf.Create {
				log.Printf("[dryrun] Userplex would have added %s to GitHub organization %s and teams %v", user, org.Name, org.Teams)
			} else if r.Conf.Create {
				r.notify(user, fmt.Sprintf("Userplex added %s to GitHub organization %s and teams %v", user, org.Name, org.Teams))
			}
		}
		for user := range membersMap {
			var userTeams []string
			// icky iterating over all these teams
			for _, team := range teamsMap {
				if _, ok := teamMembersMap[*team.Name][user]; ok {
					userTeams = append(userTeams, *team.Name)
				}
			}
			// if the member is not in ldap and is in the userplex team
			_, isUserplexed := teamMembersMap[r.p.UserplexTeamName][user]
			if !membersMap[user] && isUserplexed {
				log.Printf("[info] user %v is not in ldap groups %v but is a userplexed member of github organization %s and teams %v", user, r.Conf.LdapGroups, org.Name, userTeams)
				if !r.Conf.ApplyChanges && r.Conf.Delete {
					log.Printf("[dryrun] Userplex would have removed %s from GitHub organization %s", user, org.Name)
				}
				if r.Conf.ApplyChanges && r.Conf.Delete && 1 == 0 {
					resp, err = r.ghclient.Organizations.RemoveOrgMembership(org.Name, user)
					if err != nil || resp.StatusCode != 200 {
						log.Printf("[error] github: could not remove user %s from %s, error: %v with status %s", user, org.Name, err, resp.Status)
						continue
					}
					r.notify(user, fmt.Sprintf("Userplex removed %s to GitHub organization %s", user, org.Name))
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

func (r *run) getOrgMembersMap(org organization) (membersMap map[string]bool) {
	membersMap = make(map[string]bool)
	members, resp, err := r.ghclient.Organizations.ListMembers(org.Name, &github.ListMembersOptions{
		ListOptions: github.ListOptions{
			PerPage: 500,
		},
	})
	if err != nil || resp.StatusCode != 200 {
		log.Printf("[error] github: could not list members for organization %s, error: %v with status %s", org, err, resp.Status)
		return
	}
	for _, member := range members {
		membersMap[*member.Login] = false
	}
	return membersMap
}

func (r *run) getTeamMembersMap(team *github.Team) (membersMap map[string]bool) {
	membersMap = make(map[string]bool)
	members, resp, err := r.ghclient.Organizations.ListTeamMembers(*team.ID, &github.OrganizationListTeamMembersOptions{
		ListOptions: github.ListOptions{
			PerPage: 500,
		},
	})
	if err != nil || resp.StatusCode != 200 {
		log.Printf("[error] github: could not list members for organization %s, error: %v with status %s", team, err, resp.Status)
	}
	for _, member := range members {
		membersMap[*member.Login] = false
	}
	return membersMap
}

func (r *run) getOrgTeamsMap(org organization) (teamsMap map[string]*github.Team) {
	teamsMap = make(map[string]*github.Team)
	teams, resp, err := r.ghclient.Organizations.ListTeams(org.Name, &github.ListOptions{
		PerPage: 500,
	})
	if err != nil || resp.StatusCode != 200 {
		log.Printf("[error] github: could not list teams for organization %s, error: %v", org.Name, err)
	}
	for _, team := range teams {
		teamsMap[*team.Name] = team
	}
	log.Printf("[info] github: found %d teams for organization %s", len(teams), org.Name)
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
