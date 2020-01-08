package aws

import (
	"testing"

	"go.mozilla.org/person-api"

	"go.mozilla.org/userplex/modules"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/stretchr/testify/assert"
)

type mockIam struct {
	iamiface.IAMAPI
	getUserOutput         *iam.GetUserOutput
	listUsersOutput       *iam.ListUsersOutput
	getLoginProfileOutput *iam.GetLoginProfileOutput

	usersCreated         int
	accessKeysCreated    int
	loginProfilesCreated int
	groupsAddedTo        int

	accessKeysDeleted    int
	mfaDeviceDeactivated int
	userPolicyDeleted    int
	userPolicyDetached   int
	userGroupRemoved     int
	loginProfileDeleted  int
	userDeleted          int
}

func (m *mockIam) GetUser(*iam.GetUserInput) (*iam.GetUserOutput, error) {
	return m.getUserOutput, nil
}

func (m *mockIam) GetLoginProfile(*iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	return m.getLoginProfileOutput, nil
}

func (m *mockIam) CreateAccessKey(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	m.accessKeysCreated++
	return &iam.CreateAccessKeyOutput{
		AccessKey: &iam.AccessKey{
			AccessKeyId:     aws.String("accesskey"),
			SecretAccessKey: aws.String("secretkey"),
		},
	}, nil
}

func (m *mockIam) CreateUser(*iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	m.usersCreated++
	return nil, nil
}

func (m *mockIam) CreateLoginProfile(*iam.CreateLoginProfileInput) (*iam.CreateLoginProfileOutput, error) {
	m.loginProfilesCreated++
	return nil, nil
}

func (m *mockIam) AddUserToGroup(*iam.AddUserToGroupInput) (*iam.AddUserToGroupOutput, error) {
	m.groupsAddedTo++
	return nil, nil
}

func (m *mockIam) ListAccessKeys(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []*iam.AccessKeyMetadata{{AccessKeyId: aws.String("test")}},
	}, nil
}

func (m *mockIam) DeleteAccessKey(*iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	m.accessKeysDeleted++
	return nil, nil
}

func (m *mockIam) ListMFADevices(*iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	return &iam.ListMFADevicesOutput{
		MFADevices: []*iam.MFADevice{{SerialNumber: aws.String("test")}},
	}, nil
}

func (m *mockIam) DeactivateMFADevice(*iam.DeactivateMFADeviceInput) (*iam.DeactivateMFADeviceOutput, error) {
	m.mfaDeviceDeactivated++
	return nil, nil
}

func (m *mockIam) ListUserPolicies(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{
		PolicyNames: []*string{aws.String("test")},
	}, nil
}

func (m *mockIam) DeleteUserPolicy(*iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	m.userPolicyDeleted++
	return nil, nil
}

func (m *mockIam) ListAttachedUserPolicies(*iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{
		AttachedPolicies: []*iam.AttachedPolicy{{PolicyArn: aws.String("test")}},
	}, nil
}

func (m *mockIam) DetachUserPolicy(*iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
	m.userPolicyDetached++
	return nil, nil
}

func (m *mockIam) ListGroupsForUser(lgfui *iam.ListGroupsForUserInput) (*iam.ListGroupsForUserOutput, error) {
	if *lgfui.UserName == "extra_groups" {
		return &iam.ListGroupsForUserOutput{
			Groups: []*iam.Group{{GroupName: aws.String("test")}, {GroupName: aws.String("extra_groups")}},
		}, nil
	}
	return &iam.ListGroupsForUserOutput{
		Groups: []*iam.Group{{GroupName: aws.String("test")}},
	}, nil
}

func (m *mockIam) RemoveUserFromGroup(*iam.RemoveUserFromGroupInput) (*iam.RemoveUserFromGroupOutput, error) {
	m.userGroupRemoved++
	return nil, nil
}

func (m *mockIam) DeleteLoginProfile(*iam.DeleteLoginProfileInput) (*iam.DeleteLoginProfileOutput, error) {
	m.loginProfileDeleted++
	return nil, nil
}

func (m *mockIam) DeleteUser(*iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	m.userDeleted++
	return nil, nil
}

func (m *mockIam) ListUsers(*iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	return m.listUsersOutput, nil
}

type mockEc2 struct {
	ec2iface.EC2API
}

func TestCreate(t *testing.T) {
	username := "test"
	person := &person_api.Person{
		AccessInformation: person_api.AccessInformationValuesArray{
			LDAP: person_api.LDAPAttribute{Values: map[string]interface{}{"test": nil}},
		},
		SSHPublicKeys: person_api.StandardAttributeValues{
			Values: map[string]interface{}{},
		},
	}

	iamMock := mockIam{}

	awsm := &AWSModule{
		BaseModule: &modules.BaseModule{},
		iam:        &iamMock,
		ec2:        mockEc2{},
		config: &modules.AWSConfiguration{
			GroupMappings: []modules.GroupMapping{
				{LdapGroup: "test", IamGroups: []string{"test"}},
			},
		},
	}
	err := awsm.Create(username, person)

	assert.NoError(t, err)

	assert.Equal(t, 1, iamMock.usersCreated)
	assert.Equal(t, 1, iamMock.accessKeysCreated)
	assert.Equal(t, 1, iamMock.loginProfilesCreated)
	assert.Equal(t, 1, iamMock.groupsAddedTo)
}

func TestCreateAlreadyExists(t *testing.T) {
	username := "test"
	person := &person_api.Person{
		AccessInformation: person_api.AccessInformationValuesArray{
			LDAP: person_api.LDAPAttribute{Values: map[string]interface{}{"test": nil}},
		},
	}

	iamMock := mockIam{getUserOutput: &iam.GetUserOutput{User: &iam.User{UserName: aws.String("test")}}}

	awsm := &AWSModule{
		BaseModule: &modules.BaseModule{},
		iam:        &iamMock,
		ec2:        mockEc2{},
		config: &modules.AWSConfiguration{
			GroupMappings: []modules.GroupMapping{
				{LdapGroup: "test", IamGroups: []string{"test"}},
			},
		},
	}

	err := awsm.Create(username, person)

	assert.NoError(t, err)
	assert.Equal(t, 0, iamMock.usersCreated)
	assert.Equal(t, 0, iamMock.accessKeysCreated)
	assert.Equal(t, 0, iamMock.loginProfilesCreated)
	assert.Equal(t, 0, iamMock.groupsAddedTo)
}

func TestDelete(t *testing.T) {
	username := "test"

	iamMock := mockIam{}

	awsm := &AWSModule{
		BaseModule: &modules.BaseModule{},
		iam:        &iamMock,
		ec2:        mockEc2{},
		config:     &modules.AWSConfiguration{},
	}

	err := awsm.Delete(username)

	assert.NoError(t, err)

	assert.Equal(t, 1, iamMock.accessKeysDeleted)
	assert.Equal(t, 1, iamMock.mfaDeviceDeactivated)
	assert.Equal(t, 1, iamMock.userPolicyDeleted)
	assert.Equal(t, 1, iamMock.userPolicyDetached)
	assert.Equal(t, 1, iamMock.userGroupRemoved)
	assert.Equal(t, 1, iamMock.loginProfileDeleted)
	assert.Equal(t, 1, iamMock.userDeleted)
}

func TestReset(t *testing.T) {
	username := "test"
	person := &person_api.Person{
		AccessInformation: person_api.AccessInformationValuesArray{
			LDAP: person_api.LDAPAttribute{Values: map[string]interface{}{"test": nil}},
		},
		SSHPublicKeys: person_api.StandardAttributeValues{
			Values: map[string]interface{}{},
		},
	}

	iamMock := mockIam{getUserOutput: &iam.GetUserOutput{User: &iam.User{UserName: aws.String("test")}}}

	awsm := &AWSModule{
		BaseModule: &modules.BaseModule{},
		iam:        &iamMock,
		ec2:        mockEc2{},
		config: &modules.AWSConfiguration{
			GroupMappings: []modules.GroupMapping{
				{LdapGroup: "test", IamGroups: []string{"test"}},
			},
		},
	}

	err := awsm.Reset(username, person)

	assert.NoError(t, err)
	assert.Equal(t, 0, iamMock.usersCreated)
	assert.Equal(t, 1, iamMock.accessKeysDeleted)
	assert.Equal(t, 1, iamMock.accessKeysCreated)
	assert.Equal(t, 1, iamMock.loginProfilesCreated)
}

func TestVerify(t *testing.T) {
	iamMock := mockIam{
		listUsersOutput: &iam.ListUsersOutput{
			Users: []*iam.User{
				{UserName: aws.String("success")},
				{UserName: aws.String("not_in_ldap")},
				{UserName: aws.String("extra_groups")},
			},
			IsTruncated: aws.Bool(false),
		},
		getLoginProfileOutput: &iam.GetLoginProfileOutput{
			LoginProfile: &iam.LoginProfile{UserName: aws.String("...")},
		},
	}

	awsm := &AWSModule{
		BaseModule: &modules.BaseModule{},
		iam:        &iamMock,
		ec2:        mockEc2{},
		config: &modules.AWSConfiguration{
			GroupMappings: []modules.GroupMapping{
				{LdapGroup: "test", IamGroups: []string{"test"}},
				{LdapGroup: "extra", IamGroups: []string{"extra"}},
			},
			BaseConfiguration: modules.BaseConfiguration{UsernameMap: []modules.Umap{}},
		},
	}

	ldapUsers := []*person_api.Person{
		{
			UserID: person_api.StandardAttributeString{Value: "ad|Mozilla-LDAP|success"},
			AccessInformation: person_api.AccessInformationValuesArray{
				LDAP: person_api.LDAPAttribute{Values: map[string]interface{}{"test": nil}},
			},
		},
		{
			UserID: person_api.StandardAttributeString{Value: "ad|Mozilla-LDAP|extra_groups"},
			AccessInformation: person_api.AccessInformationValuesArray{
				LDAP: person_api.LDAPAttribute{Values: map[string]interface{}{"test": nil}},
			},
		},
	}

	verifyResults, err := awsm.verifyAWSUsers(ldapUsers)
	assert.NoError(t, err)

	assert.Len(t, verifyResults, 2)
	for _, result := range verifyResults {
		if result.AWSUsername == "not_in_ldap" {
			assert.True(t, result.NotInLDAP)
			assert.False(t, result.ExtraGroups)
		}
		if result.AWSUsername == "extra_groups" {
			assert.False(t, result.NotInLDAP)
			assert.True(t, result.ExtraGroups)
		}
	}
}
