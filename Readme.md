# Userplex [![GoDoc](https://godoc.org/github.com/mozilla-services/userplex?status.svg)](https://godoc.org/github.com/mozilla-services/userplex)

Propagate users from LDAP to Puppet, AWS, Github, Datadog, ...

## Configuration

### Ldap

How to connect to the LDAP source.
* `uri` is the connection string that uses the format
  `<protocol>://<hostname>(:<port>)/<basedn>`
* `username` the DN of the bind user
* `password` the password of the bind user
* `insecure` disables cert verification (chain of trust and name mismatch) when
  using TLS or StartTLS
* `starttls` enables starttls when the protocol is `ldap` (if the protocol is
  `ldaps`, then regular tls is used).
If a client cert is needed, put the path to the cert in `tlscert` and the path
to the key in `tlskey`.

Example:

```yaml
ldap:
    uri: "ldap://myldap.example.net/dc=example,dc=net"
    username: "uid=bind-user,ou=logins,dc=example,dc=net"
    password: "ohg81w0yofhd0193tyedlgh279eoqhsd"
    insecure: false
    starttls: true
    tlscert:  /etc/userplex/cert.crt
    tlskey:   /etc/userplex/cert.key
```

### Modules

Each module is documented in its own modules/<modulename> directory.

The base module configuration uses the following parameters:

* `name` is a module name that must map to a module in `modules/<modulename>`
* `ldapgroups` is a list of ldap group DNs
* `create` indicates whether user create is enabled
* `delete` indicates whether user deletion is enabled
* `uidmap` is a mapping of UIDs as described in the next section
* `credentials` contains module-specific credentials
* `parameters` contains module-specific parameters

```yaml
modules:
    - name: aws
      ldapgroups:
        - mysysadmins
        - thedevelopers
      create: true
      delete: true
      uidmap: *CUSTOMMAP1
      credentials:
          accesskey: AKIAbbbb
          secretkey: YOLOMAN
      parameters:
          assignroles:
            - ldap_managed
```

### UID Maps

By default, `userplex` will create users based on their LDAP `uid` attribute. In
some instance, you may want to use a different login name, which is where UID
Maps come in handy.

A UID map is just a mapping between a LDAP UID `ldapuid` and an effective UID
`useduid`. The map is defined with a custom name and references in modules.

```yaml
mycustomawsuidmap1: &CUSTOMMAP1
    - ldapuid: bkelso
      useduid: bob

    - ldapuid: tanderson
      useduid: neo

modules:
    - name: authorizedkeys
      uidmap: *CUSTOMMAP1
      ...
```
The map above will translate the ldap uids `bkelso` and `tanderson` into `bob`
and `neo`, and then create the authorizedkeys files with the translated uids.


### Notifications

Userplex provides a simple way for modules to send notifications to their users
when accounts are created and deleted.

Modules only need to send a notification in a channel provided by the main
userplex program, and don't need to know how to speak SMTP or other notification
protocol. Notifications are aggregated per user, such that N notifications to a
given user will only result in a single notification being sent, to reduce noise.

Userplex can also encrypt notifications with the user's public PGP key. This
requires two things:

1. the user must have a public PGP fingerprint in LDAP (see
   `mozldap.GetUserPGPFingerprint()` ).

2. the module must set `modules.Notifications.MustEncrypt=true` when publishing
   the notification in the channel.

When aggregating notifications, Userplex will PGP encrypt the notification body
with the user's public key if at least one notification requires encryption.

The AWS module is an example of requiring encryption, because it sends user
credentials upon creation of an account.

## Writing modules

A module must import `github.com/mozilla-services/userplex/modules`.

A module registers itself at runtime via its `init()` function which must
call `modules.Register` with a module name and an instance implementing
`modules.Moduler`.

```go
package datadog

func init() {
	modules.Register("datadog", new(module))
}

type module struct {
}
```

A module must have a unique name. A good practice is to use the same name for
the module name as for the Go package name. However, it is possible for a
single Go package to implement multiple modules, simply by registering
different Modulers with different names.

### Configuration

Modules get their configuration from the `modules.Configuration` struct passed
by the main program. The configuration contains a LDAP handler that is already
connected. Module-specific parameters go under the `Parameters` interface, and
module-specific credentials under the `Credentials` interface.

Example with the `aws` module:

```go
package aws

import (
    "github.com/mozilla-services/userplex/modules"
    //... other imports
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

// parameters are specific to the aws module and need to be accessed
// used r.Conf.GetParameters(&params) as show in Run()
type parameters struct {
	IamGroups      []string
	NotifyNewUsers bool
	SmtpRelay      string
	SmtpFrom       string
	AccountName    string
}

// same logic as for the parameters
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

    // We are setup, start doing work

    // connect an IAM client using the credentials
	var awsconf aws.Config
	if r.c.AccessKey != "" && r.c.SecretKey != "" {
		awscreds := awscred.NewStaticCredentials(r.c.AccessKey, r.c.SecretKey, "")
		awsconf.Credentials = awscreds
	}
	r.cli = iam.New(&awsconf)
	if r.cli == nil {
		return fmt.Errorf("failed to connect to aws using access key %q", r.c.AccessKey)
	}

	// Retrieve a list of ldap users from the groups configured
	ldapers = make(map[string]bool)
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
		ldapers[uid] = true
	}

    // create or add the users to groups.
	for uid, _ := range ldapers {
		resp, err := r.cli.GetUser(&iam.GetUserInput{
			UserName: aws.String(uid),
		})
		if err != nil || resp == nil {
			log.Printf("[info] user %q not found, needs to be created", uid)
			r.createIamUser(uid)
            // send a notification to the  user
            r.Conf.Notify.Channel <- modules.Notification{
                Module:      "aws",
                Recipient:   usermail,
                Mode:        r.Conf.Notify.Mode,
                MustEncrypt: true,
                Body: []byte(fmt.Sprintf(`New AWS account:
                    login: %s
                    pass:  %s (change at first login)
                    url:   %s`,
                    uid, password,
                    fmt.Sprintf("https://%s.signin.aws.amazon.com/console", r.p.AccountName))),
            }
		} else {
			r.updateUserGroups(uid)
		}
	}

    // etc...

	return
}
```

### Sending notifications

Modules receives a notification channel in `run.Conf.Notify.Channel` that
accepts messages of type `modules.Notification`. Sending notifications to users
is just a matter of publishing into that channel, and Userplex does the rest.

```go
rcpt := r.Conf.Notify.Recipient
if rcpt == "{ldap:mail}" {
	rcpt = myuseremail
}
r.Conf.Notify.Channel <- modules.Notification{
	Module:      "mymodule",
	Recipient:   rcpt,
	Mode:        r.Conf.Notify.Mode,
	MustEncrypt: true,
	Body: []byte(fmt.Sprintf(`New MyModule account:
login: %s
pass:  %s (change at first login)
url:   %s`, uid, password, url)),
	}
```

## License
Mozilla Public License 2.0

## Authors
Julien Vehent <ulfr@mozilla.com>
