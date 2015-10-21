AWS Module
==========
This module creates and deletes users from aws accounts based on LDAP groups.

The target aws account is defined by an access key and a secret key in the
`credentials` section of the module configuration.

```yaml
modules:
    - name: aws
      credentials:
          accesskey: AKIAnnnn
          secretkey: YOLOMAN
```
Alternatively, you can leave these parameters blank and set the credentials
in the environment of the user running `userplex`. More info on the [AWS blog](http://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs).

IAM Groups
----------
You need at least one IAM group to store the users managed by userplex. Call
it `ldapmanaged`, for example, and configure `userplex` as follows:

```yaml
modules:
    - name: aws
      ldapgroups:
        - sysadmins
      create: true
      delete: true
          iamgroups:
            - ldapmanaged
```
`userplex` will create all the users present in the `sysadmins` ldap group
and add them into the `ldapmanaged` aws iam group. This allows `userplex`
to later remove users from the `ldapmanaged` group that have been removed
from ldap, and delete their aws account.

Notifications
-------------
New users receive a random password that must be changed at first login.
The password can be communicated to them by email if the notification
parameters are set.
```yaml
modules:
    - name: aws
      parameters:
          notifynewusers: true
          smtpfrom: "User Operations <userops+userplex@example.net>"
          smtprelay: "localhost:25"
          signinurl: "https://myawsaccount.signin.aws.amazon.com/console"
```
Users will receive an email similar to the one below:
```
Hi jvehent,

Your AWS account has been created.
login: jvehent
pass:  P80d78fafed1b003d%
url:   https://myawsaccount.signin.aws.amazon.com/console

Your password will be changed at first login.

To use the AWS API, create Access Keys in your profile:
https://console.aws.amazon.com/iam/home#users/jvehent

Reply to this email if you have any issue connecting.

The Userplex Script.
```
