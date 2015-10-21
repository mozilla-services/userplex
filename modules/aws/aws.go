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
	"net/smtp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awsutil"
	awscred "github.com/aws/aws-sdk-go/aws/credentials"
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
	SigninUrl      string
}

type credentials struct {
	AccessKey string
	SecretKey string
}

func (r *run) Run() (err error) {
	var (
		params parameters
		creds  credentials
	)
	err = r.Conf.GetParameters(&params)
	if err != nil {
		return
	}
	r.p = params
	err = r.Conf.GetCredentials(&creds)
	if err != nil {
		return
	}
	r.c = creds
	r.cli = r.initIamClient()
	if r.cli == nil {
		return fmt.Errorf("failed to connect to aws using access key %q", r.c.AccessKey)
	}
	// Retrieve a list of ldap users from the groups configured
	// and create or add the users to groups.
	ldapers := r.getLdapers()
	for uid, _ := range ldapers {
		resp, err := r.cli.GetUser(&iam.GetUserInput{
			UserName: aws.String(uid),
		})
		if err != nil || resp == nil {
			log.Printf("[info] user %q not found, needs to be created", uid)
			r.createIamUser(uid)
		} else {
			r.updateUserGroups(uid)
		}
	}
	// find which users are no longer in ldap and needs to be removed from aws
	if r.Conf.Delete {
		iamers := r.getIamers()
		for uid, _ := range iamers {
			if _, ok := ldapers[uid]; !ok {
				log.Printf("[info] %q found in IAM group but not in LDAP, needs deletion", uid)
				r.removeIamUser(uid)
			}
		}
	}
	return
}

func (r *run) getLdapers() (lgm map[string]bool) {
	lgm = make(map[string]bool)
	users, err := r.Conf.LdapCli.GetUsersInGroups(r.Conf.LdapGroups)
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
				uid = mapping.UsedUid
			}
		}
		lgm[uid] = true
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
	return iam.New(&awsconf)
}

// create a user in aws, assign temporary credentials and force password change, add the
// user to the necessary groups, and send it an email
func (r *run) createIamUser(uid string) {
	if !r.Conf.Create {
		return
	}
	password := "P" + randToken() + "%"
	mail, err := r.Conf.LdapCli.GetUserEmailByUid(uid)
	if err != nil {
		log.Printf("[error] couldn't find email of user %q in ldap, notification not sent: %v", uid, err)
		return
	}
	if r.Conf.DryRun {
		log.Printf("[dryrun] would have created AWS IAM user %q with password %q and sent notification to %q", uid, password, mail)
		return
	}
	resp1, err := r.cli.CreateUser(&iam.CreateUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || resp1 == nil {
		log.Printf("[error] failed to create user %q: %v", uid, err)
		return
	}
	resp2, err := r.cli.CreateLoginProfile(&iam.CreateLoginProfileInput{
		Password:              aws.String(password),
		UserName:              aws.String(uid),
		PasswordResetRequired: aws.Bool(true),
	})
	if err != nil || resp2 == nil {
		log.Printf("[error] failed to create user %q: %v", uid, err)
		return
	}
	for _, group := range r.p.IamGroups {
		r.addUserToIamGroup(uid, group)
	}
	// notify user by email
	err = r.sendMail(mail, uid, password)
	if err != nil {
		log.Printf("[error] failed to send mail notification to %q: %v", mail, err)
		return
	} else {
		log.Printf("[info] notification sent to %q for user %q", mail, uid)
	}
	return
}

func (r *run) updateUserGroups(uid string) {
	gresp, err := r.cli.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || gresp == nil {
		log.Printf("[info] groups of user %q not found, needs to be added", uid)
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
	if r.Conf.DryRun {
		log.Printf("[dryrun] would have added AWS IAM user %q to group %q", uid, group)
		return
	}
	resp, err := r.cli.AddUserToGroup(&iam.AddUserToGroupInput{
		GroupName: aws.String(group),
		UserName:  aws.String(uid),
	})
	if err != nil || resp == nil {
		log.Printf("[error] failed to add user %q to group %q: %v", uid, group, err)
	}
	return
}

func (r *run) removeIamUser(uid string) {
	if !r.Conf.Delete {
		return
	}
	if r.Conf.DryRun {
		log.Printf("[dryrun] would have deleted AWS IAM user %q", uid)
		return
	}
	gresp, err := r.cli.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || gresp == nil {
		log.Printf("[error] failed to list groups for user %q: %v", uid, err)
		return
	}
	// iterate through the groups and find the missing ones
	for _, iamgroup := range r.p.IamGroups {
		resp, err := r.cli.RemoveUserFromGroup(&iam.RemoveUserFromGroupInput{
			GroupName: &iamgroup,
			UserName:  aws.String(uid),
		})
		gname := strings.Replace(awsutil.Prettify(iamgroup), `"`, ``, -1)
		if err != nil || resp == nil {
			log.Printf("[error] failed to remove user %q from group %q: %v", uid, gname, err)
		} else {
			log.Printf("[info] removed user %q from group %q", uid, gname)
		}
	}
	resp1, err := r.cli.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
		UserName: aws.String(uid),
	})
	if err != nil || resp1 == nil {
		log.Printf("[error] failed to delete aws login profile for user %q: %v", uid, err)
		return
	}
	resp2, err := r.cli.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(uid),
	})
	if err != nil || resp2 == nil {
		log.Printf("[error] failed to delete aws user %q: %v", uid, err)
		return
	}
	return
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (r *run) sendMail(rcpt, uid, password string) (err error) {
	if !r.p.NotifyNewUsers {
		log.Printf("[warn] notification of new users is disabled. password for user %q is %q", uid, password)
		return
	}
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(r.p.SmtpRelay)
	if err != nil {
		return
	}

	// Set the sender and recipient first
	err = c.Mail(r.p.SmtpFrom)
	if err != nil {
		return
	}
	err = c.Rcpt(rcpt)
	if err != nil {
		return
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		return
	}
	_, err = fmt.Fprintf(wc, `From: %s
Subject: AWS Account creation notice
Hi %s,

Your AWS account has been created.
login: %s
pass:  %s
url:   %s

Your password will be changed at first login.

To use the AWS API, create Access Keys in your profile:
https://console.aws.amazon.com/iam/home#users/%s

Reply to this email if you have any issue connecting.

The Userplex Script.`,
		r.p.SmtpFrom, uid, uid, password, r.p.SigninUrl, uid)

	if err != nil {
		return
	}
	err = wc.Close()
	if err != nil {
		return
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		return
	}
	return
}
