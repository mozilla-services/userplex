# Userplex

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


```yaml
ldap:
    uri: "ldap://myldap.example.net/dc=example,dc=net"
    username: "uid=bind-user,ou=logins,dc=example,dc=net"
    password: "ohg81w0yofhd0193tyedlgh279eoqhsd"
    insecure: false
    starttls: true
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


## Writing modules

A module must import `github.com/mozilla-server/userplex/modules`.

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

The sole method of a Moduler creates a new instance to represent a "run" of the
module, implementing the `modules.Runner` interface:

```go
// Runner provides the interface to an execution of a module
type Runner interface {
	Run() error
}
```

Any run-specific information should be associated with this instance and not with
the Moduler or stored in a global variable.  It should be possible for multiple
runs of the module to execute simultaneously.

### Configuration

Modules get their configuration from the `modules.Configuration` struct passed
by the main program. The configuration contains a LDAP handler that is already
connected. Module-specific parameters go under the `Parameters` interface, and
module-specific credentials under the `Credentials` interface.

Example with the `aws` module:

```go
package aws

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
	SigninUrl      string
}

// same logic as for the parameters
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
		} else {
			r.updateUserGroups(uid)
		}
	}

    // etc...

	return
}
```

## License
Mozilla Public License 2.0

## Authors
Julien Vehent <ulfr@mozilla.com>
