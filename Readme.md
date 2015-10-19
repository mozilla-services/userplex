Userplex
--------
Propagate users from LDAP to Puppet, AWS, Github, Datadog, ...

Configuration
-------------

Ldap
~~~~

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

Modules
~~~~~~~

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

UID Maps
~~~~~~~~
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

License
-------
Mozilla Public License 2.0

Authors
-------
Julien Vehent <ulfr@mozilla.com>
