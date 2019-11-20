package aws

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"go.mozilla.org/person-api"

	"go.mozilla.org/userplex/modules"
	"go.mozilla.org/userplex/notifications"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/awsutil"
	"github.com/aws/aws-sdk-go/aws/credentials"
	awscred "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"

	log "github.com/sirupsen/logrus"
)

type AWSModule struct {
	*modules.BaseModule
	config *modules.AWSConfiguration
	iam    *iam.IAM
	ec2    *ec2.EC2
}

func (awsm *AWSModule) NewFromInterface(config modules.Configuration, notificationsConfig notifications.Config, PersonClient *person_api.Client) modules.Module {
	return New(config.(modules.AWSConfiguration), notificationsConfig, PersonClient)
}

func New(c modules.AWSConfiguration, notificationsConfig notifications.Config, PersonClient *person_api.Client) *AWSModule {
	awsm := &AWSModule{config: &c, BaseModule: &modules.BaseModule{Notifications: notificationsConfig, PersonClient: PersonClient}}

	err := awsm.config.Validate()
	if err != nil {
		log.Fatalf("AWS userplex config failed validation: %s", err)
	}

	awsconf := aws.NewConfig().WithRegion("us-east-1")
	sess := session.New()
	if c.Credentials.AccessKey != "" && c.Credentials.SecretKey != "" {
		creds := awscred.NewStaticCredentials(c.Credentials.AccessKey, c.Credentials.SecretKey, "")
		awsconf = awsconf.WithCredentials(creds)
	} else if c.Credentials.RoleARN != "" {
		sess, err = awsm.createStsSession(awsconf, sess)
		if err != nil {
			log.Fatalf("Failed to assume AWS role %s: %s", c.Credentials.RoleARN, err)
		}
	} else {
		log.Info("Credentials not found in userplex config, using default local aws authentication flow.")
	}

	awsm.ec2 = ec2.New(sess, awsconf)
	awsm.iam = iam.New(sess, awsconf)

	return awsm
}

func (awsm *AWSModule) createStsSession(config *aws.Config, sess *session.Session) (*session.Session, error) {
	stsService := sts.New(sess)
	name := "userplex"
	out, err := stsService.AssumeRole(&sts.AssumeRoleInput{RoleArn: &awsm.config.Credentials.RoleARN, RoleSessionName: &name})
	if err != nil {
		return nil, fmt.Errorf("Failed to assume role %q: %v", awsm.config.Credentials.RoleARN, err)
	}
	config.Credentials = credentials.NewStaticCredentials(*out.Credentials.AccessKeyId, *out.Credentials.SecretAccessKey, *out.Credentials.SessionToken)
	sess, err = session.NewSession(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new aws session: %v", err)
	}
	return sess, nil
}

func (awsm *AWSModule) Create(username string, person *person_api.Person) error {
	localUsername := awsm.LDAPUsernameToLocalUsername(username, awsm.config.UsernameMap)

	if len(awsm.getUsersIAMGroups(person)) == 0 {
		return fmt.Errorf("User %s does not have any matching IAM groups and there is no default group mapping in the config file.", username)
	}

	resp, err := awsm.iam.GetUser(&iam.GetUserInput{UserName: aws.String(localUsername)})

	if err != nil || resp == nil {
		log.Infof("aws %q: user %q not found, needs to be created",
			awsm.config.AccountName, localUsername)
		return awsm.createIamUser(localUsername, person)
	}
	log.Infof("aws %q: user %q found, doing nothing.",
		awsm.config.AccountName, localUsername)
	return nil
}

// create a user in aws, assign temporary credentials and force password change, add the
// user to the necessary groups, and send it an email
func (awsm *AWSModule) createIamUser(username string, person *person_api.Person) error {
	password := "P" + randToken() + "%"
	body := fmt.Sprintf(`New AWS account:
login: %s
pass:  %s (change at first login)
url:   https://%s.signin.aws.amazon.com/console`, username, password, awsm.config.AccountName)

	cuo, err := awsm.iam.CreateUser(&iam.CreateUserInput{
		UserName: aws.String(username),
	})
	if err != nil || cuo == nil {
		log.Errorf("aws %q: failed to create user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}
	clpo, err := awsm.iam.CreateLoginProfile(&iam.CreateLoginProfileInput{
		Password:              aws.String(password),
		UserName:              aws.String(username),
		PasswordResetRequired: aws.Bool(true),
	})
	if err != nil || clpo == nil {
		log.Errorf("aws %q: failed to create user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}

	for _, group := range awsm.getUsersIAMGroups(person) {
		awsm.addUserToIamGroup(username, group)
	}

	cako, err := awsm.iam.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: aws.String(username),
	})
	if err != nil || cako == nil {
		log.Errorf("aws %q: failed to access key for user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}
	accessKeyText := fmt.Sprintf(`
Add the lines below to ~/.aws/credentials
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s`,
		awsm.config.AccountName,
		*cako.AccessKey.AccessKeyId,
		*cako.AccessKey.SecretAccessKey)

	sshkeys := person.GetSSHPublicKeys()
	sshKeyText := fmt.Sprintf("\nCreated the following AWS SSH keys from your SSH keys in LDAP:")
	createdKeys := false
	for i, key := range sshkeys {
		keyname := username + "-key-" + strconv.Itoa(i)
		ikpo, err := awsm.ec2.ImportKeyPair(&ec2.ImportKeyPairInput{
			KeyName:           aws.String(keyname),
			PublicKeyMaterial: []byte(key),
		})
		if err != nil || ikpo == nil {
			if awsErr, ok := err.(awserr.Error); ok {
				if awsErr.Code() == "InvalidKeyPair.Duplicate" {
					continue
				}
			}
			log.Errorf("aws %q: failed to create SSH key %s for user %q: %v",
				awsm.config.AccountName, keyname, username, err)
			return err
		}
		sshKeyText += fmt.Sprintf("\n%s, MD5 Fingerprint: %s", *ikpo.KeyName, *ikpo.KeyFingerprint)
	}
	if !createdKeys {
		sshKeyText = ""
	}

	if awsm.config.NotifyNewUsers {
		return awsm.Notify(username, strings.Join([]string{body, accessKeyText, sshKeyText}, "\n"), person)
	} else {
		fmt.Println("Notify new users disabled, printing output.")
		fmt.Printf("Created new user: %s\n", username)
		fmt.Printf("Email body: \n%s", strings.Join([]string{body, accessKeyText, sshKeyText}, "\n"))
		eb, err := notifications.EncryptMailBody(awsm.Notifications, []byte(strings.Join([]string{body, accessKeyText, sshKeyText}, "\n")), person)
		if err != nil {
			log.Errorf("Error encrypted email body: %s", err)
			return err
		}
		fmt.Printf("Encrypted email body: \n%s", eb)
	}

	return nil
}

func (awsm *AWSModule) Reset(username string, person *person_api.Person) error {
	localUsername := awsm.LDAPUsernameToLocalUsername(username, awsm.config.UsernameMap)
	return awsm.resetIamUser(localUsername, person)
}

func (awsm *AWSModule) Delete(username string) error {
	localUsername := awsm.LDAPUsernameToLocalUsername(username, awsm.config.UsernameMap)
	return awsm.deleteIamUser(localUsername)
}

func (awsm *AWSModule) addUserToIamGroup(username, group string) error {
	resp, err := awsm.iam.AddUserToGroup(&iam.AddUserToGroupInput{
		GroupName: aws.String(group),
		UserName:  aws.String(username),
	})
	if err != nil || resp == nil {
		log.Errorf("aws %q: failed to add user %q to group %q: %v",
			awsm.config.AccountName, username, group, err)
		return err
	}
	return nil
}

func (awsm *AWSModule) deleteIamUser(username string) error {
	var (
		err  error
		lgfu *iam.ListGroupsForUserOutput
		dlpo *iam.DeleteLoginProfileOutput
		duo  *iam.DeleteUserOutput
		dako *iam.DeleteAccessKeyOutput
		rufg *iam.RemoveUserFromGroupOutput
	)
	// remove all user's access keys
	lakfu, err := awsm.iam.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil || lakfu == nil {
		log.Errorf("aws %q: failed to list access keys for user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}
	for _, accesskey := range lakfu.AccessKeyMetadata {
		keyid := strings.Replace(awsutil.Prettify(accesskey.AccessKeyId), `"`, ``, -1)
		daki := iam.DeleteAccessKeyInput{
			AccessKeyId: accesskey.AccessKeyId,
			UserName:    aws.String(username),
		}
		dako, err = awsm.iam.DeleteAccessKey(&daki)
		if err != nil || dako == nil {
			log.Errorf("aws %q: failed to delete access key %q of user %q: %v. request was %q.",
				awsm.config.AccountName, keyid, username, err, daki.String())
		} else {
			log.Debugf("aws %q: deleted access key %q of user %q",
				awsm.config.AccountName, keyid, username)
		}

	}
	// remove the user from all IAM groups
	lgfu, err = awsm.iam.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: aws.String(username),
	})
	if err != nil || lgfu == nil {
		log.Errorf("aws %q: failed to list groups for user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}
	// iterate through the groups and find the missing ones
	for _, iamgroup := range lgfu.Groups {
		gname := strings.Replace(awsutil.Prettify(iamgroup.GroupName), `"`, ``, -1)
		rufgi := &iam.RemoveUserFromGroupInput{
			GroupName: iamgroup.GroupName,
			UserName:  aws.String(username),
		}
		rufg, err = awsm.iam.RemoveUserFromGroup(rufgi)
		if err != nil || rufg == nil {
			log.Errorf("aws %q: failed to remove user %q from group %q: %v. request was %q.",
				awsm.config.AccountName, username, gname, err, rufgi.String())
		} else {
			log.Debugf("aws %q: removed user %q from group %q",
				awsm.config.AccountName, username, gname)
		}
	}
	dlpo, err = awsm.iam.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil || dlpo == nil {
		log.Debugf("aws %q: user %q did not have an aws login profile to delete",
			awsm.config.AccountName, username)
	}
	duo, err = awsm.iam.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(username),
	})
	if err != nil || duo == nil {
		log.Errorf("aws %q: failed to delete aws user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}
	log.Infof("aws %q: deleted user %q", awsm.config.AccountName, username)
	return nil
}

// reset the password for a user in aws
// assign temporary credentials and force password change
// send it an email
func (awsm *AWSModule) resetIamUser(username string, person *person_api.Person) error {
	password := "P" + randToken() + "%"
	body := fmt.Sprintf(`Updated AWS account:
login: %s
pass:  %s (change at first login)
url:   https://%s.signin.aws.amazon.com/console`, username, password, awsm.config.AccountName)

	loginProfile, err := awsm.iam.GetLoginProfile(&iam.GetLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		log.Errorf("aws %q: failed to create login profile for user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}

	if loginProfile == nil {
		cLoginProfileResp, err := awsm.iam.CreateLoginProfile(&iam.CreateLoginProfileInput{
			Password:              aws.String(password),
			UserName:              aws.String(username),
			PasswordResetRequired: aws.Bool(true),
		})
		if err != nil || cLoginProfileResp == nil {
			log.Errorf("aws %q: failed to create login profile for user %q: %v",
				awsm.config.AccountName, username, err)
			return err
		}
	} else {
		uLoginProfileResp, err := awsm.iam.UpdateLoginProfile(&iam.UpdateLoginProfileInput{
			Password:              aws.String(password),
			UserName:              aws.String(username),
			PasswordResetRequired: aws.Bool(true),
		})
		if err != nil || uLoginProfileResp == nil {
			log.Errorf("aws %q: failed to update login profile for user %q: %v",
				awsm.config.AccountName, username, err)
			return err
		}
	}

	listAccessKeysResp, err := awsm.iam.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		log.Errorf("aws %q: failed to list access keys for user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}

	// delete all access keys associated with the user
	for _, key := range listAccessKeysResp.AccessKeyMetadata {
		deleteAccessKeyInput := iam.DeleteAccessKeyInput{
			AccessKeyId: key.AccessKeyId,
			UserName:    aws.String(username),
		}
		dako, err := awsm.iam.DeleteAccessKey(&deleteAccessKeyInput)
		if err != nil || dako == nil {
			log.Errorf("aws %q: failed to delete access key %q of user %q: %v. request was %q.",
				awsm.config.AccountName, *key.AccessKeyId, username, err, deleteAccessKeyInput.String())
		} else {
			log.Debugf("aws %q: deleted access key %q of user %q",
				awsm.config.AccountName, *key.AccessKeyId, username)
		}
	}

	createAccessKeyResp, err := awsm.iam.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: aws.String(username),
	})
	if err != nil || createAccessKeyResp == nil {
		log.Errorf("aws %q: failed to create access key for user %q: %v",
			awsm.config.AccountName, username, err)
		return err
	}

	accesskey := fmt.Sprintf(`
A new access key has been created for you.
Add the lines below to ~/.aws/credentials
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s`,
		awsm.config.AccountName,
		*createAccessKeyResp.AccessKey.AccessKeyId,
		*createAccessKeyResp.AccessKey.SecretAccessKey)

	if awsm.config.NotifyNewUsers {
		return awsm.Notify(username, strings.Join([]string{body, accesskey}, "\n"), person)
	} else {
		fmt.Println("Notify new users disabled, printing output.")
		fmt.Printf("Reset user: %s\n", username)
		fmt.Printf("Email body: \n%s", strings.Join([]string{body, accesskey}, "\n"))
		eb, err := notifications.EncryptMailBody(awsm.Notifications, []byte(strings.Join([]string{body, accesskey}, "\n")), person)
		if err != nil {
			log.Errorf("Error encrypted email body: %s", err)
			return err
		}
		fmt.Printf("Encrypted email body: \n%s", eb)
	}

	return nil
}

func (awsm *AWSModule) getUsersIAMGroups(person *person_api.Person) []string {
	var iamGroups []string
	for group := range person.AccessInformation.LDAP.Values {
		for _, grpMapping := range awsm.config.GroupMapping {
			if grpMapping.LdapGroup == group {
				for _, g := range grpMapping.IamGroups {
					iamGroups = append(iamGroups, g)
				}
			}
		}
	}
	if len(iamGroups) == 0 {
		for _, grpMapping := range awsm.config.GroupMapping {
			if grpMapping.Default {
				return unique(grpMapping.IamGroups)
			}
		}
	}
	return unique(iamGroups)
}

func (awsm *AWSModule) Sync() error {
	_, notInLdap, _, err := awsm.verifyAndPrint()
	if err != nil {
		return err
	}

	fmt.Printf("Would you like to remove these users from AWS account with name %s?\n", awsm.config.AccountName)
	for _, u := range notInLdap {
		fmt.Printf("	* %s\n", u)
	}

	var response string
	for response != "y" && response != "n" {
		fmt.Printf("(y/n): ")
		_, err := fmt.Scanln(&response)
		if err != nil {
			return err
		}
	}
	if response == "n" {
		fmt.Println("Got 'no' response. Quiting...")
		return nil
	}

	for _, u := range notInLdap {
		err = awsm.deleteIamUser(u)
		if err != nil {
			log.Errorf("Error deleting user %s: %s", u, err)
			return err
		}
	}

	return nil
}

type VerifyResult struct {
	AWSUsername string
	NotInLDAP   bool
	ExtraGroups bool
}

func (awsm *AWSModule) Verify() error {
	_, _, _, err := awsm.verifyAndPrint()
	return err
}

func (awsm *AWSModule) verifyAndPrint() ([]VerifyResult, []string, []string, error) {
	results, err := awsm.verifyAWSUsers()
	if err != nil {
		log.Errorf("Error verifying aws users: %s", err)
		return nil, nil, nil, err
	}

	usersNotInLdap := []string{}
	usersWithExtraGroups := []string{}
	for _, result := range results {
		if result.NotInLDAP {
			usersNotInLdap = append(usersNotInLdap, result.AWSUsername)
		}
		if result.ExtraGroups {
			usersWithExtraGroups = append(usersWithExtraGroups, result.AWSUsername)
		}
	}

	if len(usersNotInLdap) > 0 {
		fmt.Println("Users not in LDAP:")
		for _, u := range usersNotInLdap {
			fmt.Printf("	* %s\n", u)
		}
	}

	if len(usersWithExtraGroups) > 0 {
		fmt.Println("Users with additional groups:")
		for _, u := range usersWithExtraGroups {
			fmt.Printf("	* %s\n", u)
		}
	}

	return results, usersNotInLdap, usersWithExtraGroups, nil
}

func (awsm *AWSModule) getAllAWSUsersWithConsoleAccess() ([]*iam.User, error) {
	var (
		allIAMUsers []*iam.User
		iamUsers    []*iam.User
	)

	usersOutput, err := awsm.iam.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		log.Errorf("Error getting users from AWS: %s", err)
		return nil, err
	}
	allIAMUsers = usersOutput.Users
	if *usersOutput.IsTruncated {
		for {
			usersOutput, err = awsm.iam.ListUsers(&iam.ListUsersInput{Marker: usersOutput.Marker})
			if err != nil {
				log.Errorf("Error getting users from AWS: %s", err)
				return nil, err
			}
			for _, u := range usersOutput.Users {
				allIAMUsers = append(allIAMUsers, u)
			}
			if !*usersOutput.IsTruncated {
				break
			}
		}
	}

	for _, user := range allIAMUsers {
		loginProfileOutput, err := awsm.iam.GetLoginProfile(&iam.GetLoginProfileInput{UserName: user.UserName})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == iam.ErrCodeNoSuchEntityException {
					continue
				}
			}
			log.Errorf("Error getting login profiles from AWS: %s", err)
			return nil, err
		}
		if loginProfileOutput != nil && loginProfileOutput.LoginProfile.UserName != nil {
			iamUsers = append(iamUsers, user)
		}
	}

	return iamUsers, nil
}

func (awsm *AWSModule) verifyAWSUsers() ([]VerifyResult, error) {
	var (
		verifyResults []VerifyResult
		ldapUsernames map[string]*person_api.Person
	)

	iamUsers, err := awsm.getAllAWSUsersWithConsoleAccess()
	if err != nil {
		log.Errorf("Error getting users from AWS: %s", err)
		return nil, err
	}

	allLdapUsers, err := awsm.PersonClient.GetAllActiveStaff()
	if err != nil {
		log.Errorf("Error getting users from Person API: %s", err)
		return nil, err
	}

	for _, ldapUser := range allLdapUsers {
		ldapUsernames[awsm.LDAPUsernameToLocalUsername(ldapUser.GetLDAPUsername(), awsm.config.UsernameMap)] = ldapUser
	}

	for _, user := range iamUsers {
		inLdap := false
		vr := VerifyResult{AWSUsername: *user.UserName}

		for ldapUsername, person := range ldapUsernames {
			if *user.UserName == ldapUsername {
				inLdap = true

				// Check group membership
				expectedGroups := awsm.getUsersIAMGroups(person)
				groupsOutput, err := awsm.iam.ListGroupsForUser(&iam.ListGroupsForUserInput{UserName: user.UserName})
				if err != nil {
					log.Errorf("Error getting list of groups for user %s: %s", *user.UserName, err)
					return nil, err
				}
				for _, group := range groupsOutput.Groups {
					found := false
					// Check for extra goups that the user wasn't expected to have.
					for _, eg := range expectedGroups {
						if *group.GroupName == eg {
							found = true
							break
						}
					}

					if !found {
						vr.ExtraGroups = true
						verifyResults = append(verifyResults, vr)
						break
					}
				}

				break
			}
		}
		if !inLdap {
			vr.NotInLDAP = true
			verifyResults = append(verifyResults, vr)
		}
	}

	return verifyResults, nil
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func unique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
