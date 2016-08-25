AWS Module
==========
This module creates, deletes, and resets users from aws accounts based on LDAP groups,
and sent notifications to newly created users with their temporary password.

Important note: because notifications contain passwords, this module requires
users to have a PGP public key uploaded on gpg.mozilla.org, and its fingerprint
publishes in LDAP.

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
      reset: true
      parameters:
          iamgroups:
            - ldapmanaged
```
`userplex` will create all the users present in the `sysadmins` ldap group
and add them into the `ldapmanaged` aws iam group. This allows `userplex`
to later remove users from the `ldapmanaged` group that have been removed
from ldap, and delete their aws account.

Reset
-------------------
AWS user accounts can be reset by passing their LDAP uid to the `-reset` `userplex` command line flag.
The `reset` module configuration must be set to `true` for `-reset` to be active.

Access key creation
-------------------
This module can create an access key when a user is created. The access key will
be sent to the user in the body of the encrypted notification. To activate this
feature, set `createaccesskey: true` in the configuration parameters.

```yaml
modules:
    - name: aws
      parameters:
          createaccesskey: true
```

Notifications
-------------
This module supports standard userplex notifications. When notifications are
enabled, users are required to have a pgp fingerprint in LDAP because the
notification body contains credentials that must be encrypted.

The name of the AWS account is also needed to point users to the location of the
AWS console.

```yaml
modules:
    - name: aws
      notify:
        mode: smtp
        recipient: "{ldap:mail}"
      parameters:
          accountname: cloudservices-aws-dev

```
Notifications are sent on creation and reset of user accounts. No notification is
sent on deletion of an account.

The notification contains a username, a temporary password which must be changed
at first connection, a signin URL and a pair of API access/secret keys.

Because it contains secrets, the notification is required to be encrypted with
the public PGP key of the user (see main userplex documentation).
