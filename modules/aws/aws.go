// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package aws // import "go.mozilla.org/userplex/modules/aws"

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
	"go.mozilla.org/userplex/modules"
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
	IamGroups       []string
	AccountName     string
	CreateAccessKey bool
}

type credentials struct {
	AccessKey string
	SecretKey string
}

func (r *run) Run() (err error) {
	var (
		countCreated, countGroupUpdated, countDeleted, countReset int
		iamers                                                    map[string]bool
	)
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

	// Retrieve a list of iam users from the groups configured
	if r.Conf.Delete || r.Conf.Reset {
		iamers = r.getIamers()
	}
	// create or add the users to groups.
	if r.Conf.Create {
		for uid, haspubkey := range ldapers {
			resp, err := r.cli.GetUser(&iam.GetUserInput{
				UserName: aws.String(uid),
			})
			if err != nil || resp == nil {
				log.Printf("[info] aws %q: user %q not found, needs to be created",
					r.p.AccountName, uid)
				if !haspubkey && r.Conf.NotifyUsers {
					log.Printf("[warning] aws %q: %q has no PGP fingerprint in LDAP, skipping creation",
						r.p.AccountName, uid)
					continue
				}
				r.createIamUser(uid)
				countCreated++
			} else {
				if r.updateUserGroups(uid) {
					countGroupUpdated++
				}
			}
		}
	}
	// find which users are no longer in ldap and needs to be removed from aws
	if r.Conf.Delete {
		for uid, _ := range iamers {
			if _, ok := ldapers[uid]; !ok {
				r.debug("aws %q: %q found in IAM group but not in LDAP, needs deletion",
					r.p.AccountName, uid)
				r.removeIamUser(uid)
				countDeleted++
			}
		}
	}
	// reset access key and password for specified user
	if r.Conf.Reset && r.Conf.ResetUsername != "" {
		if _, ok := iamers[r.Conf.ResetUsername]; ok {
			r.debug("aws %q: %q found, needs reset",
				r.p.AccountName, r.Conf.ResetUsername)
			r.resetIamUser(r.Conf.ResetUsername)
			countReset++
		} else {
			log.Printf("[warning] aws %q: %q wanted reset but could not be found",
				r.p.AccountName, r.Conf.ResetUsername)
		}
	}
	log.Printf("[info] aws %q: summary created=%d, group_updated=%d, deleted=%d, reset=%d",
		r.p.AccountName, countCreated, countGroupUpdated, countDeleted, countReset)
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
			log.Printf("[error] aws %q: ldap query failed with error %v", r.p.AccountName, err)
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
				r.debug("aws %q: no pgp public key could be found for %s: %v",
					r.p.AccountName, shortdn, err)
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
			log.Printf("[error] aws %q: failed to retrieve users from IAM group %q: %v",
				r.p.AccountName, group, err)
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
		accesskey string
		cuo       *iam.CreateUserOutput
		clpo      *iam.CreateLoginProfileOutput
		cako      *iam.CreateAccessKeyOutput
	)
	password := "P" + randToken() + "%"
	mail, err := r.Conf.LdapCli.GetUserEmailByUid(uid)
	if err != nil {
		log.Printf("[error] aws %q: couldn't find email of user %q in ldap, notification not sent: %v",
			r.p.AccountName, uid, err)
		return
	}
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws %q: would have created AWS IAM user %q with password %q",
			r.p.AccountName, uid, password)
		goto notify
	}
	cuo, err = r.cli.CreateUser(&iam.CreateUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || cuo == nil {
		log.Printf("[error] aws %q: failed to create user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	clpo, err = r.cli.CreateLoginProfile(&iam.CreateLoginProfileInput{
		Password:              aws.String(password),
		UserName:              aws.String(uid),
		PasswordResetRequired: aws.Bool(true),
	})
	if err != nil || clpo == nil {
		log.Printf("[error] aws %q: failed to create user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	for _, group := range r.p.IamGroups {
		r.addUserToIamGroup(uid, group)
	}
	if r.p.CreateAccessKey {
		cako, err = r.cli.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: aws.String(uid),
		})
		if err != nil || cako == nil {
			log.Printf("[error] aws %q: failed to access key for user %q: %v",
				r.p.AccountName, uid, err)
			return
		}
		accesskey = fmt.Sprintf(`
Add the lines below to ~/.aws/credentials
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s`,
			r.p.AccountName,
			*cako.AccessKey.AccessKeyId,
			*cako.AccessKey.SecretAccessKey)
	}

notify:
	// notify user
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		rcpt = mail
	}

	body := fmt.Sprintf(`New AWS account:
login: %s
pass:  %s (change at first login)
url:   https://%s.signin.aws.amazon.com/console
%s`, uid, password, r.p.AccountName, accesskey)

	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "aws",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: true,
		Body:        []byte(body),
	}
	return
}

func (r *run) updateUserGroups(uid string) (updated bool) {
	gresp, err := r.cli.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || gresp == nil {
		r.debug("aws %q: groups of user %q not found, needs to be added",
			r.p.AccountName, uid)
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
			updated = true
		}
	}
	return
}

func (r *run) addUserToIamGroup(uid, group string) {
	if !r.Conf.Create {
		return
	}
	if !r.Conf.ApplyChanges {
		r.debug("aws %q: would have added AWS IAM user %q to group %q",
			r.p.AccountName, uid, group)
		return
	}
	resp, err := r.cli.AddUserToGroup(&iam.AddUserToGroupInput{
		GroupName: aws.String(group),
		UserName:  aws.String(uid),
	})
	if err != nil || resp == nil {
		log.Printf("[error] aws %q: failed to add user %q to group %q: %v",
			r.p.AccountName, uid, group, err)
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
		log.Printf("[error] aws %q: failed to list access keys for user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	for _, accesskey := range lakfu.AccessKeyMetadata {
		keyid := strings.Replace(awsutil.Prettify(accesskey.AccessKeyId), `"`, ``, -1)
		if !r.Conf.ApplyChanges {
			r.debug("[dryrun] aws %q: would have removed access key id %q of user %q",
				r.p.AccountName, keyid, uid)
			continue
		}
		daki := &iam.DeleteAccessKeyInput{
			AccessKeyId: accesskey.AccessKeyId,
			UserName:    aws.String(uid),
		}
		resp, err := r.cli.DeleteAccessKey(daki)
		if err != nil || resp == nil {
			log.Printf("[error] aws %q: failed to delete access key %q of user %q: %v. request was %q.",
				r.p.AccountName, keyid, uid, err, daki.String())
		} else {
			r.debug("aws %q: deleted access key %q of user %q",
				r.p.AccountName, keyid, uid)
		}

	}
	// remove the user from all IAM groups
	lgfu, err = r.cli.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || lgfu == nil {
		log.Printf("[error] aws %q: failed to list groups for user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	// iterate through the groups and find the missing ones
	for _, iamgroup := range lgfu.Groups {
		gname := strings.Replace(awsutil.Prettify(iamgroup.GroupName), `"`, ``, -1)
		if !r.Conf.ApplyChanges {
			r.debug("[dryrun] aws %q: would have removed user %q from group %q",
				r.p.AccountName, uid, gname)
			continue
		}
		rufgi := &iam.RemoveUserFromGroupInput{
			GroupName: iamgroup.GroupName,
			UserName:  aws.String(uid),
		}
		resp, err := r.cli.RemoveUserFromGroup(rufgi)
		if err != nil || resp == nil {
			log.Printf("[error] aws %q: failed to remove user %q from group %q: %v. request was %q.",
				r.p.AccountName, uid, gname, err, rufgi.String())
		} else {
			r.debug("aws %q: removed user %q from group %q",
				r.p.AccountName, uid, gname)
		}
	}
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws %q: would have deleted AWS IAM user %q",
			r.p.AccountName, uid)
		goto notify
	}
	dlpo, err = r.cli.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
		UserName: aws.String(uid),
	})
	if err != nil || dlpo == nil {
		r.debug("aws %q: user %q did not have an aws login profile to delete",
			r.p.AccountName, uid)
	}
	duo, err = r.cli.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || duo == nil {
		log.Printf("[error] aws %q: failed to delete aws user %q: %v",
			r.p.AccountName, uid, err)
		return
	} else {
		log.Printf("[info] aws %q: deleted user %q", r.p.AccountName, uid)
	}
notify:
	// notify user
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		rcpt, err = r.Conf.LdapCli.GetUserEmailByUid(uid)
		if err != nil {
			log.Printf("[error] aws %q: couldn't find email of user %q in ldap, notification not sent: %v",
				r.p.AccountName, uid, err)
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

// reset the password for a user in aws
// assign temporary credentials and force password change
// send it an email
func (r *run) resetIamUser(uid string) {
	var (
		accesskey      string
		accessKeyLimit = 2
		cako           *iam.CreateAccessKeyOutput
		glpo           *iam.GetLoginProfileOutput
		ulpo           *iam.UpdateLoginProfileOutput
		clpo           *iam.CreateLoginProfileOutput
		laao           *iam.ListAccessKeysOutput
	)

	password := "P" + randToken() + "%"
	mail, err := r.Conf.LdapCli.GetUserEmailByUid(uid)
	if err != nil {
		log.Printf("[error] aws %q: couldn't find email of user %q in ldap, notification not sent: %v",
			r.p.AccountName, uid, err)
		return
	}
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws %q: would have reset AWS IAM user %q with password %q",
			r.p.AccountName, uid, password)
		goto notify
	}
	glpo, err = r.cli.GetLoginProfile(&iam.GetLoginProfileInput{
		UserName: aws.String(uid),
	})
	if err != nil {
		log.Printf("[error] aws %q: failed to create login profile for user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	if glpo == nil {
		clpo, err = r.cli.CreateLoginProfile(&iam.CreateLoginProfileInput{
			Password:              aws.String(password),
			UserName:              aws.String(uid),
			PasswordResetRequired: aws.Bool(true),
		})
		if err != nil || clpo == nil {
			log.Printf("[error] aws %q: failed to create login profile for user %q: %v",
				r.p.AccountName, uid, err)
			return
		}
	} else {
		ulpo, err = r.cli.UpdateLoginProfile(&iam.UpdateLoginProfileInput{
			Password:              aws.String(password),
			UserName:              aws.String(uid),
			PasswordResetRequired: aws.Bool(true),
		})
		if err != nil || ulpo == nil {
			log.Printf("[error] aws %q: failed to update login profile for user %q: %v",
				r.p.AccountName, uid, err)
			return
		}
	}
	if r.p.CreateAccessKey {
		laao, err = r.cli.ListAccessKeys(&iam.ListAccessKeysInput{
			UserName: aws.String(uid),
		})
		if err != nil || laao == nil {
			log.Printf("[error] aws %q: failed to list access keys for user %q: %v",
				r.p.AccountName, uid, err)
			return
		}
		// only create an access key if user has fewer than
		// hardcoded default # of access keys per user per
		// http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html
		if len(laao.AccessKeyMetadata) > accessKeyLimit {
			log.Printf("[warning] aws %q: %q already has max of %d access keys",
				r.p.AccountName, uid, accessKeyLimit)
		} else {
			cako, err = r.cli.CreateAccessKey(&iam.CreateAccessKeyInput{
				UserName: aws.String(uid),
			})
			if err != nil || cako == nil {
				log.Printf("[error] aws %q: failed to create access key for user %q: %v",
					r.p.AccountName, uid, err)
				return
			}
			accesskey = fmt.Sprintf(`
	A new access key has been created for you.
	Add the lines below to ~/.aws/credentials
	[%s]
	aws_access_key_id = %s
	aws_secret_access_key = %s`,
				r.p.AccountName,
				*cako.AccessKey.AccessKeyId,
				*cako.AccessKey.SecretAccessKey)
		}
	}

notify:
	// notify user
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		rcpt = mail
	}

	body := fmt.Sprintf(`Updated AWS account:
login: %s
pass:  %s (change at first login)
url:   https://%s.signin.aws.amazon.com/console
%s`, uid, password, r.p.AccountName, accesskey)

	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "aws",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: true,
		Body:        []byte(body),
	}
	return
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (r *run) debug(format string, a ...interface{}) {
	if r.Conf.Debug {
		log.Printf("[debug] "+format, a...)
	}
}
