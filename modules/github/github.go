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
	Conf         modules.Configuration
	p            parameters
	c            credentials
	ghclient     *github.Client
	githubToLdap map[string]string
	ldapToGithub map[string]string
}

type organization struct {
	Name  string
	Teams []string
}

type parameters struct {
	Organizations    []organization
	UserplexTeamName string
	Enforce2FA       bool
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

	r.buildLdapMapping()
	ldapers := r.getLdapers()

	for _, org := range r.p.Organizations {
		// get all members for the organization
		// name -> bool
		membersMap := r.getOrgMembersMap(org, "all")
		log.Printf("[info] github: found %d users for organization %s", len(membersMap), org.Name)

		// get all teams for the organization
		// name -> team
		teamsMap := r.getOrgTeamsMap(org)
		log.Printf("[info] github: found %d teams for organization %s", len(teamsMap), org.Name)

		teamMembersMap := make(map[string]map[string]bool)
		for _, team := range teamsMap {
			teamMembersMap[*team.Name] = make(map[string]bool)
			teamMembersMap[*team.Name] = r.getTeamMembersMap(team)
		}

		if _, ok := teamsMap[r.p.UserplexTeamName]; !ok {
			log.Printf("[error] github: could not find UserplexTeam \"%s\" for organization %s", r.p.UserplexTeamName, org.Name)
			// skip org
			continue
		}
		userplexedUsers := teamMembersMap[r.p.UserplexTeamName]

		var no2fa map[string]bool
		if r.p.Enforce2FA {
			no2fa = r.getOrgMembersMap(org, "2fa_disabled")
			log.Printf("[info] github: organization %s has %d total members and %d with 2fa disabled. %.2f%% have 2fa enabled.",
				org.Name, len(membersMap), len(no2fa), 100-100*float64(len(no2fa))/float64(len(membersMap)))
		}

		// member or admin
		membershipType := "member"

		for user := range ldapers {
			// set to true to indicate that user in github has ldap match
			membersMap[user] = true

			userWasAddedToTeam := false
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
					if r.Conf.Create {
						userWasAddedToTeam = true
					}
				}
			}
			if userWasAddedToTeam {
				log.Printf("[dryrun] github: would have added %s to GitHub organization %s and teams %v", user, org.Name, org.Teams)
				r.notify(user, fmt.Sprintf("Userplex added %s to GitHub organization %s and teams %v", user, org.Name, org.Teams))
			}
		}

		for member := range membersMap {
			// if the member is not in the userplex team
			_, isUserplexed := userplexedUsers[member]
			if !isUserplexed {
				if r.Conf.Debug {
					log.Printf("[debug] github: skipping member %s in organization %s because they are not in UserplexTeam %s", member, org.Name, r.p.UserplexTeamName)
				}
				continue
			}

			var ldapUsername, ldapUsernameString string
			member = strings.ToLower(member)
			if _, ok := r.githubToLdap[member]; ok {
				ldapUsername = r.githubToLdap[member]
				ldapUsernameString = ldapUsername + " / "
			}

			var userTeams []string
			// icky iterating over all these teams
			for _, team := range teamsMap {
				if _, ok := teamMembersMap[*team.Name][member]; ok {
					userTeams = append(userTeams, *team.Name)
				}
			}

			// if the member does not have 2fa
			_, no2fa := no2fa[member]

			// if the user is in ldap
			_, inLdap := membersMap[member]

			if !inLdap || r.p.Enforce2FA && no2fa {
				if !inLdap {
					log.Printf("[info] user %s%s is not in ldap groups %s but is a member of github organization %s and teams %v", ldapUsernameString, member, r.Conf.LdapGroups, org.Name, userTeams)
				}
				if r.p.Enforce2FA && no2fa {
					log.Printf("[info] user %s%s does not have 2FA enabled and is a member of github organization %s and teams %v", ldapUsernameString, member, org.Name, userTeams)
				}
				if r.Conf.Delete {
					if !r.Conf.ApplyChanges {
						log.Printf("[dryrun] Userplex would have removed %s from GitHub organization %s", member, org.Name)
					} else {
						resp, err = r.ghclient.Organizations.RemoveOrgMembership(org.Name, member)
						if err != nil || resp.StatusCode != 200 {
							log.Printf("[error] github: could not remove user %s from %s, error: %v with status %s", member, org.Name, err, resp.Status)
							continue
						}
					}
					r.notify(member, fmt.Sprintf("Userplex removed %s to GitHub organization %s", member, org.Name))
				}
			}
		}
	}

	return nil
}

func (r *run) buildLdapMapping() {
	r.githubToLdap = make(map[string]string)
	r.ldapToGithub = make(map[string]string)
	for _, mapping := range r.Conf.UidMap {
		r.githubToLdap[mapping.LocalUID] = mapping.LdapUid
		r.ldapToGithub[mapping.LdapUid] = mapping.LocalUID
	}
}

func (r *run) getOrgMembersMap(org organization, filter string) (membersMap map[string]bool) {
	membersMap = make(map[string]bool)
	opt := &github.ListMembersOptions{
		Filter:      filter,
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		members, resp, err := r.ghclient.Organizations.ListMembers(org.Name, opt)
		if err != nil || resp.StatusCode != 200 {
			log.Printf("[error] github: could not list members for organization %s, error: %v with status %s", org, err, resp.Status)
			return
		}
		for _, member := range members {
			membersMap[*member.Login] = false
		}
		if resp.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = resp.NextPage
	}
	return membersMap
}

func (r *run) getTeamMembersMap(team *github.Team) (membersMap map[string]bool) {
	membersMap = make(map[string]bool)
	opt := &github.OrganizationListTeamMembersOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	for {
		members, resp, err := r.ghclient.Organizations.ListTeamMembers(*team.ID, opt)
		if err != nil || resp.StatusCode != 200 {
			log.Printf("[error] github: could not list members for organization %s, error: %v with status %s", team, err, resp.Status)
		}
		for _, member := range members {
			membersMap[*member.Login] = false
		}
		if resp.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = resp.NextPage
	}
	return membersMap
}

func (r *run) getOrgTeamsMap(org organization) (teamsMap map[string]*github.Team) {
	teamsMap = make(map[string]*github.Team)
	opt := &github.ListOptions{
		PerPage: 100,
	}
	for {
		teams, resp, err := r.ghclient.Organizations.ListTeams(org.Name, opt)
		if err != nil || resp.StatusCode != 200 {
			log.Printf("[error] github: could not list teams for organization %s, error: %v", org.Name, err)
		}
		for _, team := range teams {
			teamsMap[*team.Name] = team
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return teamsMap
}

func (r *run) notify(user string, body string) (err error) {
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		if _, ok := r.githubToLdap[user]; ok {
			user = r.githubToLdap[user]
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

		if _, ok := r.ldapToGithub[uid]; ok {
			uid = r.ldapToGithub[uid]
		}

		lgm[uid] = false
	}
	return
}
