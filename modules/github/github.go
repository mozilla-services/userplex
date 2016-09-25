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
}

type organization struct {
	Name  string
	Teams []string
}

type parameters struct {
	Organization     organization
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

	// initialize mapping of github usernames -> ldap uids
	r.githubToLdap = make(map[string]string)
	ldapers := r.getLdapers()

	// get all members for the organization
	// name -> bool
	membersMap := r.getOrgMembersMap(r.p.Organization, "all")
	if r.Conf.Debug {
		log.Printf("[debug] github: found %d users for organization %s", len(membersMap), r.p.Organization.Name)
	}

	// get all teams for the organization
	// name -> team
	teamsMap := r.getOrgTeamsMap(r.p.Organization)
	if r.Conf.Debug {
		log.Printf("[debug] github: found %d teams for organization %s", len(teamsMap), r.p.Organization.Name)
	}

	teamMembersMap := make(map[string]map[string]bool)
	for _, team := range teamsMap {
		teamMembersMap[*team.Name] = make(map[string]bool)
		teamMembersMap[*team.Name] = r.getTeamMembersMap(team)
	}

	if _, ok := teamsMap[r.p.UserplexTeamName]; !ok {
		return fmt.Errorf("[error] github: could not find UserplexTeam \"%s\" for organization %s", r.p.UserplexTeamName, r.p.Organization.Name)
	}
	userplexedUsers := teamMembersMap[r.p.UserplexTeamName]

	var no2fa map[string]bool
	if r.p.Enforce2FA {
		no2fa = r.getOrgMembersMap(r.p.Organization, "2fa_disabled")
		log.Printf("[info] github: organization %s has %d total members and %d with 2fa disabled. %.2f%% have 2fa enabled.",
			r.p.Organization.Name, len(membersMap), len(no2fa), 100-100*float64(len(no2fa))/float64(len(membersMap)))
	}

	// member or admin
	membershipType := "member"

	countAdded := 0
	for user := range ldapers {
		// set to true to indicate that user in github has ldap match
		membersMap[user] = true

		userWasAddedToTeam := false
		// teams in config
		for _, teamName := range r.p.Organization.Teams {
			// if the team in config doesn't exist on github
			if team, ok := teamsMap[teamName]; !ok {
				return fmt.Errorf("[error] github: could not find team %s for organization %s", team, r.p.Organization.Name)
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
						return fmt.Errorf("[error] github: could not add user %s to %s: %s, error: %v with status %s", user, r.p.Organization.Name, *team.Name, err, resp.Status)
					}
				}
				if r.Conf.Create {
					userWasAddedToTeam = true
				}
			}
		}
		if userWasAddedToTeam {
			if !r.Conf.ApplyChanges {
				log.Printf("[dryrun] github: would have added %s to GitHub organization %s and teams %v", user, r.p.Organization.Name, r.p.Organization.Teams)
			}
			countAdded++
			r.notify(user, fmt.Sprintf("Userplex added %s to GitHub organization %s and teams %v", user, r.p.Organization.Name, r.p.Organization.Teams))
		}
	}

	countRemoved := 0
	countSkipped := 0
	for member := range membersMap {
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

		// if the member is not in the userplex team
		_, isUserplexed := userplexedUsers[member]

		shouldDelete := false
		if !inLdap {
			if r.Conf.Debug {
				log.Printf("[debug] github: user %s%s is not in ldap groups %s but is a member of github organization %s and teams %v", ldapUsernameString, member, r.Conf.LdapGroups, r.p.Organization.Name, userTeams)
			}
			shouldDelete = true
		}

		if r.p.Enforce2FA && no2fa {
			log.Printf("[info] github: user %s%s does not have 2FA enabled and is a member of github organization %s and teams %v", ldapUsernameString, member, r.p.Organization.Name, userTeams)
			shouldDelete = true
		}

		if shouldDelete && r.Conf.Delete {
			// not in UserplexTeam -> skip
			if !isUserplexed {
				log.Printf("[info] github: would have removed member %s in organization %s, but skipped because they are not in UserplexTeam %q", member, r.p.Organization.Name, r.p.UserplexTeamName)
				countSkipped++
				continue
			}

			if !r.Conf.ApplyChanges {
				log.Printf("[dryrun] github: Userplex would have removed %s%s from GitHub organization %s", ldapUsernameString, member, r.p.Organization.Name)
			} else {
				// applying changes, user is userplexed -> remove them
				resp, err = r.ghclient.Organizations.RemoveOrgMembership(r.p.Organization.Name, member)
				if err != nil || resp.StatusCode != 200 {
					log.Printf("[error] github: could not remove user %s from %s, error: %v with status %s", member, r.p.Organization.Name, err, resp.Status)
				}
			}

			// update count and send notification here regardless of ApplyChanges
			countRemoved++
			r.notify(member, fmt.Sprintf("Userplex removed %s to GitHub organization %s", member, r.p.Organization.Name))
		}
	}

	log.Printf("[info] github %q: summary added=%d, removed=%d, skipped=%d",
		r.p.Organization.Name, countAdded, countRemoved, countSkipped)

	return nil
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

func (r *run) getOrgTeamsMap(org organization) (teamsMap map[string]*github.Team) {
	teamsMap = make(map[string]*github.Team)
	opt := &github.ListOptions{
		PerPage: 100,
	}
	for {
		teams, resp, err := r.ghclient.Organizations.ListTeams(org.Name, opt)
		if err != nil || resp.StatusCode != 200 {
			log.Printf("[error] github: could not list teams for organization %s, error: %v", org.Name, err)
			return
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
			return fmt.Errorf("[error] github: couldn't find email of user %q in ldap, notification not sent: %v", user, err)
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

func (r *run) getLdapers() map[string]bool {
	ldapers := make(map[string]bool)
	users, err := r.Conf.LdapCli.GetEnabledUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		return ldapers
	}
	for _, user := range users {
		shortdn := strings.Split(user, ",")[0]
		uid, err := r.Conf.LdapCli.GetUserId(shortdn)
		if err != nil {
			log.Printf("[error] github: ldap query GetUserId(%q) failed with error %v", uid, err)
			continue
		}

		github, getGithubAccountErr := r.Conf.LdapCli.GetUserGithubByUID(uid)
		if getGithubAccountErr != nil {
			// this error can happen if the user does not have a githubProfile in ldap
			if r.Conf.Debug {
				log.Printf("[debug] github: ldap query GetUserGithubByUID(%q) failed with error %q", uid, getGithubAccountErr.Error())
			}
		} else {
			// has a githubProfile in LDAP
			r.githubToLdap[github] = uid
			uid = github
		}

		ldapers[uid] = false
	}
	return ldapers
}
