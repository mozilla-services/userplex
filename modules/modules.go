package modules

import (
	"fmt"

	person_api "go.mozilla.org/person-api"
	"go.mozilla.org/userplex/notifications"

	"github.com/aws/aws-sdk-go/aws"
	awscred "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	log "github.com/sirupsen/logrus"
)

type Module interface {
	NewFromInterface(config Configuration, notificationsConfig notifications.Config, personClient *person_api.Client) Module
	Create(username string, person *person_api.Person) error
	Reset(username string, person *person_api.Person) error
	Delete(username string) error
	Sync() error
	Verify() error
	Notify(username, body string, person *person_api.Person, usePgp bool) error
	LDAPUsernameToLocalUsername(ldapUsername string, usernameMap []Umap) string
	ModuleName() string
}

type BaseModule struct {
	Notifications *notifications.Config `yaml:"notifications"`
	PersonClient  *person_api.Client
}

func (bm *BaseModule) Notify(username, body string, person *person_api.Person, usePgp bool) error {
	return notifications.SendEmail(bm.Notifications, []byte(body), person, usePgp)
}

func (bm *BaseModule) LDAPUsernameToLocalUsername(ldapUsername string, usernameMap []Umap) string {
	for _, umap := range usernameMap {
		if umap.LdapUsername == ldapUsername {
			return umap.LocalUsername
		}
	}
	return ldapUsername
}

type Configuration interface{}

type BaseConfiguration struct {
	NotifyNewUsers bool   `yaml:"notify_new_users"`
	NotifyUsePgp   bool   `yaml:"notify_use_pgp"`
	UsernameMap    []Umap `yaml:"username_map" json:"username_map"`
}

type Umap struct {
	LdapUsername  string `yaml:"ldap_username" json:"ldap_username"`
	LocalUsername string `yaml:"local_username" json:"local_username"`
}

type GroupMapping struct {
	LdapGroup string   `yaml:"ldap_group"`
	IamGroups []string `yaml:"iam_groups"`
	Default   bool     `yaml:"default"`
}

type AWSConfiguration struct {
	BaseConfiguration `yaml:",inline"`
	AccountName       string   `yaml:"account_name"`
	IgnoreUsernames   []string `yaml:"ignore_usernames"`
	Credentials       struct {
		AccessKey string `yaml:"access_key"`
		SecretKey string `yaml:"secret_key"`
		RoleARN   string `yaml:"role_arn"`
	} `yaml:"credentials"`
	GroupMappings []GroupMapping `yaml:"group_mapping"`
}

func (c *AWSConfiguration) Validate() error {
	if (c.Credentials.AccessKey != "" && c.Credentials.SecretKey != "") && c.Credentials.RoleARN != "" {
		return fmt.Errorf("Access/Secret Key combo and Role ARN found, can only have one.")
	}

	defaultFound := false
	iamGroupsSet := make(map[string]bool)
	for _, gmap := range c.GroupMappings {
		if gmap.Default {
			if defaultFound {
				return fmt.Errorf("More than one 'default' group mapping found.")
			}
			if gmap.LdapGroup != "" {
				return fmt.Errorf("'default' group mapping contains an ldap group.")
			}
			defaultFound = true
		}
		for _, iamg := range gmap.IamGroups {
			if _, v := iamGroupsSet[iamg]; !v {
				iamGroupsSet[iamg] = true
			}
		}
	}

	awsconf := aws.NewConfig().WithRegion("us-east-1")
	if c.Credentials.AccessKey != "" && c.Credentials.SecretKey != "" {
		creds := awscred.NewStaticCredentials(c.Credentials.AccessKey, c.Credentials.SecretKey, "")
		awsconf = awsconf.WithCredentials(creds)
	} else {
		log.Info("AWS credentials not found in config, using default AWS auth flow.")
	}
	svc := iam.New(session.New(), awsconf)
	for iamGroup := range iamGroupsSet {
		resp, err := svc.GetGroup(&iam.GetGroupInput{GroupName: aws.String(iamGroup)})
		if err != nil || resp == nil {
			return fmt.Errorf("Could not find AWS IAM Group %s: %s", iamGroup, err)
		}
	}

	return nil
}

type AuthorizedKeysConfiguration struct {
	BaseConfiguration `yaml:",inline"`
	Name              string   `yaml:"name"`
	LdapGroups        []string `yaml:"ldap_groups"`
	Path              string   `yaml:"path"`
}
