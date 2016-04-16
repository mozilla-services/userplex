// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package aws

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awsutil"
	awscred "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/mozilla-services/userplex/modules"
)

func init() {
	modules.Register("aws", new(module))
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
	cli  *iam.IAM
}

type parameters struct {
	IamGroups      []string
	NotifyNewUsers bool
	SmtpRelay      string
	SmtpFrom       string
	AccountName    string
}

type credentials struct {
	AccessKey string
	SecretKey string
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
	r.cli = r.initIamClient()
	if r.cli == nil {
		return fmt.Errorf("failed to connect to aws using access key %q", r.c.AccessKey)
	}
	// Retrieve a list of ldap users from the groups configured
	ldapers := r.getLdapers()
	// create or add the users to groups.
	if r.Conf.Create {
		for uid, haspubkey := range ldapers {
			resp, err := r.cli.GetUser(&iam.GetUserInput{
				UserName: aws.String(uid),
			})
			if err != nil || resp == nil {
				log.Printf("[info] aws: user %q not found, needs to be created", uid)
				if !haspubkey && r.Conf.NotifyUsers {
					log.Printf("[warning] aws: %q has no PGP fingerprint in LDAP, skipping creation", uid)
					continue
				}
				r.createIamUser(uid)
			} else {
				r.updateUserGroups(uid)
			}
		}
	}
	// find which users are no longer in ldap and needs to be removed from aws
	if r.Conf.Delete {
		iamers := r.getIamers()
		for uid, _ := range iamers {
			if _, ok := ldapers[uid]; !ok {
				log.Printf("[info] aws: %q found in IAM group but not in LDAP, needs deletion", uid)
				r.removeIamUser(uid)
			}
		}
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
			log.Printf("[warning] aws: ldap query failed with error %v", err)
			continue
		}
		// apply the uid map: only store the translated uid in the ldapuid
		for _, mapping := range r.Conf.UidMap {
			if mapping.LdapUid == uid {
				uid = mapping.LocalUID
			}
		}
		lgm[uid] = true
		if r.Conf.NotifyUsers {
			// make sure we can find a PGP public key for the user to encrypt the notification
			// if no pubkey is found, log an error and set the user's entry to False
			_, err = r.Conf.LdapCli.GetUserPGPKey(shortdn)
			if err != nil {
				log.Printf("[warning] aws: no pgp public key could be found for %s: %v", shortdn, err)
				lgm[uid] = false
			}
		}
	}
	return
}

func (r *run) getIamers() (igm map[string]bool) {
	igm = make(map[string]bool)
	for _, group := range r.p.IamGroups {
		resp, err := r.cli.GetGroup(&iam.GetGroupInput{
			GroupName: aws.String(group),
		})
		if err != nil || resp == nil {
			log.Printf("[error] failed to retrieve users from IAM group %q: %v", group, err)
			continue
		}
		for _, user := range resp.Users {
			iamuser := strings.Replace(awsutil.Prettify(user.UserName), `"`, ``, -1)
			igm[iamuser] = true
		}
	}
	return
}

func (r *run) initIamClient() *iam.IAM {
	var awsconf aws.Config
	if r.c.AccessKey != "" && r.c.SecretKey != "" {
		awscreds := awscred.NewStaticCredentials(r.c.AccessKey, r.c.SecretKey, "")
		awsconf.Credentials = awscreds
	}
	return iam.New(session.New(), &awsconf)
}

// create a user in aws, assign temporary credentials and force password change, add the
// user to the necessary groups, and send it an email
func (r *run) createIamUser(uid string) {
	var (
		cuo  *iam.CreateUserOutput
		clpo *iam.CreateLoginProfileOutput
	)
	password := "P" + randToken() + "%"
	mail, err := r.Conf.LdapCli.GetUserEmailByUid(uid)
	if err != nil {
		log.Printf("[error] aws: couldn't find email of user %q in ldap, notification not sent: %v", uid, err)
		return
	}
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws: would have created AWS IAM user %q with password %q", uid, password)
		goto notify
	}
	cuo, err = r.cli.CreateUser(&iam.CreateUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || cuo == nil {
		log.Printf("[error] aws: failed to create user %q: %v", uid, err)
		return
	}
	clpo, err = r.cli.CreateLoginProfile(&iam.CreateLoginProfileInput{
		Password:              aws.String(password),
		UserName:              aws.String(uid),
		PasswordResetRequired: aws.Bool(true),
	})
	if err != nil || clpo == nil {
		log.Printf("[error] aws: failed to create user %q: %v", uid, err)
		return
	}
	for _, group := range r.p.IamGroups {
		r.addUserToIamGroup(uid, group)
	}
notify:
	// notify user
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		rcpt = mail
	}
	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "aws",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: true,
		Body: []byte(fmt.Sprintf(`New AWS account:
login: %s
pass:  %s (change at first login)
url:   %s`, uid, password, fmt.Sprintf("https://%s.signin.aws.amazon.com/console", r.p.AccountName))),
	}
	return
}

func (r *run) updateUserGroups(uid string) {
	gresp, err := r.cli.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || gresp == nil {
		log.Printf("[info] aws: groups of user %q not found, needs to be added", uid)
	}
	// iterate through the groups and find the missing ones
	for _, iamgroup := range r.p.IamGroups {
		found := false
		for _, group := range gresp.Groups {
			gname := strings.Replace(awsutil.Prettify(group.GroupName), `"`, ``, -1)
			if iamgroup == gname {
				found = true
			}
		}
		if !found {
			r.addUserToIamGroup(uid, iamgroup)
		}
	}
	return
}

func (r *run) addUserToIamGroup(uid, group string) {
	if !r.Conf.Create {
		return
	}
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws: would have added AWS IAM user %q to group %q", uid, group)
		return
	}
	resp, err := r.cli.AddUserToGroup(&iam.AddUserToGroupInput{
		GroupName: aws.String(group),
		UserName:  aws.String(uid),
	})
	if err != nil || resp == nil {
		log.Printf("[error] aws: failed to add user %q to group %q: %v", uid, group, err)
	}
	return
}

func (r *run) removeIamUser(uid string) {
	var (
		err  error
		lgfu *iam.ListGroupsForUserOutput
		dlpo *iam.DeleteLoginProfileOutput
		duo  *iam.DeleteUserOutput
	)
	if !r.Conf.Delete {
		return
	}
	// remove all user's access keys
	lakfu, err := r.cli.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(uid),
	})
	if err != nil || lakfu == nil {
		log.Printf("[error] aws: failed to list access keys for user %q: %v", uid, err)
		return
	}
	for _, accesskey := range lakfu.AccessKeyMetadata {
		keyid := strings.Replace(awsutil.Prettify(accesskey.AccessKeyId), `"`, ``, -1)
		if !r.Conf.ApplyChanges {
			log.Printf("[dryrun] aws: would have removed access key id %q of user %q", keyid, uid)
			continue
		}
		daki := &iam.DeleteAccessKeyInput{
			AccessKeyId: accesskey.AccessKeyId,
			UserName:    aws.String(uid),
		}
		resp, err := r.cli.DeleteAccessKey(daki)
		if err != nil || resp == nil {
			log.Printf("[error] aws: failed to delete access key %q of user %q: %v. request was %q.",
				keyid, uid, err, daki.String())
		} else {
			log.Printf("[info] aws: deleted access key %q of user %q", keyid, uid)
		}

	}
	// remove the user from all IAM groups
	lgfu, err = r.cli.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || lgfu == nil {
		log.Printf("[error] aws: failed to list groups for user %q: %v", uid, err)
		return
	}
	// iterate through the groups and find the missing ones
	for _, iamgroup := range lgfu.Groups {
		gname := strings.Replace(awsutil.Prettify(iamgroup.GroupName), `"`, ``, -1)
		if !r.Conf.ApplyChanges {
			log.Printf("[dryrun] aws: would have removed user %q from group %q", uid, gname)
			continue
		}
		rufgi := &iam.RemoveUserFromGroupInput{
			GroupName: iamgroup.GroupName,
			UserName:  aws.String(uid),
		}
		resp, err := r.cli.RemoveUserFromGroup(rufgi)
		if err != nil || resp == nil {
			log.Printf("[error] aws: failed to remove user %q from group %q: %v. request was %q.",
				uid, gname, err, rufgi.String())
		} else {
			log.Printf("[info] aws: removed user %q from group %q", uid, gname)
		}
	}
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws: would have deleted AWS IAM user %q", uid)
		goto notify
	}
	dlpo, err = r.cli.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
		UserName: aws.String(uid),
	})
	if err != nil || dlpo == nil {
		log.Printf("[info] aws: user %q did not have an aws login profile to delete", uid)
	}
	duo, err = r.cli.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || duo == nil {
		log.Printf("[error] aws: failed to delete aws user %q: %v", uid, err)
		return
	} else {
		log.Printf("[info] aws: deleted user %q", uid)
	}
notify:
	// notify user
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		rcpt, err = r.Conf.LdapCli.GetUserEmailByUid(uid)
		if err != nil {
			log.Printf("[error] aws: couldn't find email of user %q in ldap, notification not sent: %v", uid, err)
			return
		}
	}
	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "aws",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: false,
		Body: []byte(fmt.Sprintf(`Deleted AWS account:
The account %q has been removed from %q.`, uid, r.p.AccountName)),
	}
	return
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
