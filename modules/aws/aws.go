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
	"github.com/aws/aws-sdk-go/service/ec2"
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
	iam  *iam.IAM
	ec2  *ec2.EC2
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
		countCreated,
		countGroupUpdated,
		countDeleted,
		countReset int
		iamers map[string]bool
	)
	err = r.Conf.GetParameters(&r.p)
	if err != nil {
		return
	}
	err = r.Conf.GetCredentials(&r.c)
	if err != nil {
		return
	}
	r.iam = r.initIamClient()
	if r.iam == nil {
		return fmt.Errorf("[error] aws iam: failed to connect to aws using access key %q", r.c.AccessKey)
	}

	r.ec2 = r.initEc2Client()
	if r.ec2 == nil {
		return fmt.Errorf("[error] aws ec2: failed to connect to aws using access key %q", r.c.AccessKey)
	}

	if r.Conf.ResetUsers != "" {
		resetUsers := strings.Split(strings.Trim(r.Conf.ResetUsers, ", "), ",")

		// reset specified users
		for _, user := range resetUsers {
			var uid string
			uid, _, err = r.getLdaperByUID(user)
			if err != nil {
				// logging happens in getLdaper
				return
			}
			r.resetIamUser(uid)
			countReset++
		}
		log.Printf("[info] aws %q: summary created=%d, deleted=%d, reset=%d",
			r.p.AccountName, countCreated, countDeleted, countReset)
		return
	}

	// Retrieve a list of ldap users from the groups configured
	ldapers := r.getLdapers()

	// create or add the users to groups.
	if r.Conf.Create {
		for uid, hasPGPKey := range ldapers {
			resp, err := r.iam.GetUser(&iam.GetUserInput{
				UserName: aws.String(uid),
			})
			if err != nil || resp == nil {
				log.Printf("[info] aws %q: user %q not found, needs to be created",
					r.p.AccountName, uid)
				if !hasPGPKey && r.Conf.NotifyUsers {
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
		// Retrieve a list of iam users from the groups configured
		iamers = r.getIamers()
		for uid := range iamers {
			if _, ok := ldapers[uid]; !ok {
				r.debug("aws %q: %q found in IAM group but not in LDAP, needs deletion",
					r.p.AccountName, uid)
				r.removeIamUser(uid)
				countDeleted++
			}
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
		uid, hasPGPKey, err := r.getLdaper(shortdn)
		if err != nil {
			// error logging happens in getLdaper
			continue
		}
		lgm[uid] = hasPGPKey
	}
	return
}

func (r *run) getLdaperByUID(ldapUserID string) (uid string, hasPGPKey bool, err error) {
	var user string
	user, err = r.Conf.LdapCli.GetUserDNById(ldapUserID)
	shortdn := strings.Split(user, ",")[0]
	if err != nil {
		log.Printf("[error] aws %q: ldap query failed with error %v", r.p.AccountName, err)
		return
	}
	return r.getLdaper(shortdn)
}

func (r *run) getLdaper(shortdn string) (uid string, hasPGPKey bool, err error) {
	uid, err = r.Conf.LdapCli.GetUserId(shortdn)
	if err != nil {
		log.Printf("[error] aws %q: ldap query failed with error %v", r.p.AccountName, err)
		return
	}
	// apply the uid map: only store the translated uid in the ldapuid
	for _, mapping := range r.Conf.UidMap {
		if mapping.LdapUid == uid {
			uid = mapping.LocalUID
		}
	}
	if r.Conf.NotifyUsers {
		// make sure we can find a PGP public key for the user to encrypt the notification
		// if no pubkey is found, log an error and set the user's entry to False
		_, pgpErr := r.Conf.LdapCli.GetUserPGPKey(shortdn)
		if pgpErr != nil {
			r.debug("aws %q: no pgp public key could be found for %s: %v",
				r.p.AccountName, shortdn, pgpErr)
		}
		hasPGPKey = true
	}
	return
}

func (r *run) getIamers() map[string]bool {
	iamers := make(map[string]bool)
	for _, group := range r.p.IamGroups {
		err := r.iam.GetGroupPages(&iam.GetGroupInput{
			GroupName: aws.String(group),
		}, func(page *iam.GetGroupOutput, lastpage bool) bool {
			for _, user := range page.Users {
				iamuser := strings.Replace(awsutil.Prettify(user.UserName), `"`, ``, -1)
				iamers[iamuser] = true
			}
			if lastpage {
				return false
			}
			return true
		})
		if err != nil {
			log.Printf("[error] aws %q: failed to retrieve users from IAM group %q: %v",
				r.p.AccountName, group, err)
			// empty map
			return make(map[string]bool)
		}
	}
	return iamers
}

func (r *run) initEc2Client() *ec2.EC2 {
	var awsconf aws.Config
	if r.c.AccessKey != "" && r.c.SecretKey != "" {
		awscreds := awscred.NewStaticCredentials(r.c.AccessKey, r.c.SecretKey, "")
		awsconf.Credentials = awscreds
	}
	return ec2.New(session.New(), &awsconf)
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
		sshKeyText    string
		accessKeyText string
		cuo           *iam.CreateUserOutput
		clpo          *iam.CreateLoginProfileOutput
		cako          *iam.CreateAccessKeyOutput
		sshkeys       []string
		ikpo          *ec2.ImportKeyPairOutput
		err           error
	)
	password := "P" + randToken() + "%"
	body := fmt.Sprintf(`New AWS account:
login: %s
pass:  %s (change at first login)
url:   https://%s.signin.aws.amazon.com/console`, uid, password, r.p.AccountName)

	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws %q: would have created AWS IAM user %q with password %q",
			r.p.AccountName, uid, password)
		// notify the user, do not apply
		r.notify(uid, body)
		return
	}
	cuo, err = r.iam.CreateUser(&iam.CreateUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || cuo == nil {
		log.Printf("[error] aws %q: failed to create user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	clpo, err = r.iam.CreateLoginProfile(&iam.CreateLoginProfileInput{
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
		cako, err = r.iam.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: aws.String(uid),
		})
		if err != nil || cako == nil {
			log.Printf("[error] aws %q: failed to access key for user %q: %v",
				r.p.AccountName, uid, err)
			return
		}
		accessKeyText = fmt.Sprintf(`
Add the lines below to ~/.aws/credentials
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s`,
			r.p.AccountName,
			*cako.AccessKey.AccessKeyId,
			*cako.AccessKey.SecretAccessKey)
	}
	sshkeys, err = r.getSSHPubKeys(uid)
	if err != nil {
		log.Printf("[error] aws %q: LDAP failed to get SSH keys for user %q: %v.",
			r.p.AccountName, uid, err)
	}
	if len(sshkeys) > 0 {
		sshKeyText = fmt.Sprintf("\nCreated the following AWS SSH keys in AWS corresponding public keys in LDAP:")
	}
	for i, key := range sshkeys {
		keyname := uid + "-key-" + string(i)
		ikpo, err = r.ec2.ImportKeyPair(&ec2.ImportKeyPairInput{
			KeyName:           aws.String(keyname),
			PublicKeyMaterial: []byte(key),
		})
		if err != nil || ikpo == nil {
			log.Printf("[error] aws %q: failed to create SSH key %s for user %q: %v",
				r.p.AccountName, keyname, uid, err)
			return
		}
		log.Printf("ikpo: %v", ikpo)
		sshKeyText += fmt.Sprintf("\n%s, MD5 Fingerprint: %s", *ikpo.KeyName, *ikpo.KeyFingerprint)
	}

	// notify the user
	r.notify(uid, strings.Join([]string{body, accessKeyText, sshKeyText}, "\n"))
}

func (r *run) updateUserGroups(uid string) (updated bool) {
	gresp, err := r.iam.ListGroupsForUser(&iam.ListGroupsForUserInput{
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
	resp, err := r.iam.AddUserToGroup(&iam.AddUserToGroupInput{
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
		dako *iam.DeleteAccessKeyOutput
		rufg *iam.RemoveUserFromGroupOutput
	)
	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws %q: would have deleted AWS IAM user %q",
			r.p.AccountName, uid)
		return
	}

	// remove all user's access keys
	lakfu, err := r.iam.ListAccessKeys(&iam.ListAccessKeysInput{
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
		daki := iam.DeleteAccessKeyInput{
			AccessKeyId: accesskey.AccessKeyId,
			UserName:    aws.String(uid),
		}
		dako, err = r.iam.DeleteAccessKey(&daki)
		if err != nil || dako == nil {
			log.Printf("[error] aws %q: failed to delete access key %q of user %q: %v. request was %q.",
				r.p.AccountName, keyid, uid, err, daki.String())
		} else {
			r.debug("aws %q: deleted access key %q of user %q",
				r.p.AccountName, keyid, uid)
		}

	}
	// remove the user from all IAM groups
	lgfu, err = r.iam.ListGroupsForUser(&iam.ListGroupsForUserInput{
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
		rufgi := &iam.RemoveUserFromGroupInput{
			GroupName: iamgroup.GroupName,
			UserName:  aws.String(uid),
		}
		rufg, err = r.iam.RemoveUserFromGroup(rufgi)
		if err != nil || rufg == nil {
			log.Printf("[error] aws %q: failed to remove user %q from group %q: %v. request was %q.",
				r.p.AccountName, uid, gname, err, rufgi.String())
		} else {
			r.debug("aws %q: removed user %q from group %q",
				r.p.AccountName, uid, gname)
		}
	}
	dlpo, err = r.iam.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
		UserName: aws.String(uid),
	})
	if err != nil || dlpo == nil {
		r.debug("aws %q: user %q did not have an aws login profile to delete",
			r.p.AccountName, uid)
	}
	duo, err = r.iam.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || duo == nil {
		log.Printf("[error] aws %q: failed to delete aws user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	log.Printf("[info] aws %q: deleted user %q", r.p.AccountName, uid)
}

// reset the password for a user in aws
// assign temporary credentials and force password change
// send it an email
func (r *run) resetIamUser(uid string) {
	var (
		accesskey string
		cako      *iam.CreateAccessKeyOutput
		glpo      *iam.GetLoginProfileOutput
		ulpo      *iam.UpdateLoginProfileOutput
		clpo      *iam.CreateLoginProfileOutput
		lako      *iam.ListAccessKeysOutput
		dako      *iam.DeleteAccessKeyOutput
		err       error
	)

	password := "P" + randToken() + "%"
	body := fmt.Sprintf(`Updated AWS account:
login: %s
pass:  %s (change at first login)
url:   https://%s.signin.aws.amazon.com/console`, uid, password, r.p.AccountName)

	if !r.Conf.ApplyChanges {
		log.Printf("[dryrun] aws %q: would have reset AWS IAM user %q with password %q",
			r.p.AccountName, uid, password)
		// notify the user, do not apply
		r.notify(uid, body)
		return
	}
	glpo, err = r.iam.GetLoginProfile(&iam.GetLoginProfileInput{
		UserName: aws.String(uid),
	})
	if err != nil {
		log.Printf("[error] aws %q: failed to create login profile for user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	if glpo == nil {
		clpo, err = r.iam.CreateLoginProfile(&iam.CreateLoginProfileInput{
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
		ulpo, err = r.iam.UpdateLoginProfile(&iam.UpdateLoginProfileInput{
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
	lako, err = r.iam.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(uid),
	})
	if err != nil || lako == nil {
		log.Printf("[error] aws %q: failed to list access keys for user %q: %v",
			r.p.AccountName, uid, err)
		return
	}
	// delete all access keys associated with the user
	for _, key := range lako.AccessKeyMetadata {
		daki := iam.DeleteAccessKeyInput{
			AccessKeyId: key.AccessKeyId,
			UserName:    aws.String(uid),
		}
		dako, err = r.iam.DeleteAccessKey(&daki)
		if err != nil || dako == nil {
			log.Printf("[error] aws %q: failed to delete access key %q of user %q: %v. request was %q.",
				r.p.AccountName, *key.AccessKeyId, uid, err, daki.String())
		} else {
			r.debug("aws %q: deleted access key %q of user %q",
				r.p.AccountName, *key.AccessKeyId, uid)
		}
	}
	if r.p.CreateAccessKey {
		cako, err = r.iam.CreateAccessKey(&iam.CreateAccessKeyInput{
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
	// notify the user
	r.notify(uid, strings.Join([]string{body, accesskey}, "\n"))
}

func (r *run) getSSHPubKeys(uid string) ([]string, error) {
	// reverse the uid map
	for _, mapping := range r.Conf.UidMap {
		if mapping.LocalUID == uid {
			uid = mapping.LdapUid
		}
	}
	dn, err := r.Conf.LdapCli.GetUserDNById(uid)
	if err != nil {
		log.Printf("[error] aws %q: LDAP failed to get DN for user %q: %v.",
			r.p.AccountName, uid, err)
	}
	shortdn := strings.Split(dn, ",")[0]
	keys, err := r.Conf.LdapCli.GetUserSSHPublicKeys(shortdn)
	return keys, err
}

func (r *run) notify(uid, body string) {
	// notify user
	rcpt := r.Conf.Notify.Recipient
	if rcpt == "{ldap:mail}" {
		// reverse the uid map
		for _, mapping := range r.Conf.UidMap {
			if mapping.LocalUID == uid {
				uid = mapping.LdapUid
			}
		}
		mail, err := r.Conf.LdapCli.GetUserEmailByUid(uid)
		if err != nil {
			log.Printf("[error] aws %q: couldn't find email of user %q in ldap, notification not sent: %v",
				r.p.AccountName, uid, err)
			return
		}
		rcpt = mail
	}

	r.Conf.Notify.Channel <- modules.Notification{
		Module:      "aws",
		Recipient:   rcpt,
		Mode:        r.Conf.Notify.Mode,
		MustEncrypt: true,
		Body:        []byte(body),
	}
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
