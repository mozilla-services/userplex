# Authorized Keys Modules

This module retrieve SSH Public Keys from LDAP and writes them into files.

The `destination` parameters indicates where the keys will be written. If the
destination contains the string `{ldap:uid}`, the string is replaced with the
value of the uid of the user (or the translated uid if a uidmap is specified).

For example:

```yaml
modules:
    - name: authorizedkeys
      parameters:
          destination: /data/puppet-config/users/modules/users/files/{ldap:uid}/.ssh/authorized_keys
```

will write authorized keys for each ldap users in their respective folder.

```bash
$ cat /data/puppet-config/users/modules/users/files/jvehent/.ssh/authorized_keys
 # jvehent LDAP pubkeys; deletionmarker=userplex_all
 ssh-rsa AAAABeUZZWgjMMx90D8p2MXVG0FgZVW8Nm6p8Vir14yFDMZLFlVmQ== Mozilla key from 2015042
 ```
 
 If the destination parameter does not contain any variable, all keys from the
 members of a group will be written into a single destination file. For example:

```yaml
    # members of sysadmins have their keys in the root authorized_keys
    - name: authorizedkeys
      ldapgroups:
        - sysadmins
      create: true
      delete: false
      parameters:
          destination: /data/puppet-config/users/modules/users/files/root/.ssh/authorized_keys
```
will produce a single file `/data/puppet-config/users/modules/users/files/root/.ssh/authorized_keys`
```bash
$ cat /data/puppet-config/users/modules/users/files/root/.ssh/authorized_keys 
# bob LDAP pubkeys
ssh-rsa AAASMveH/h+SWnx/tR bob@bob-09481.local
ssh-rsa AAAAB3Nza5iIh4lWGXFdLZOTHi8xxCC2l7r7cmXmoJzdu6/wSXKvX8= bobexample@gmail.com
# alice LDAP pubkeys
ssh-rsa AAAAB3NzaC1yc2EAphjiv alice@host-4-245.mv.mozilla.com
# eve LDAP pubkeys
ssh-rsa AAAAB3NzaC1yc2EAAAAA2j9HpReihH1d59YoGDZNZ3L59i6G7/Q== eve@minituls.co.uk
```

## Deletion Marker
When `delete: true`, this module will remove files that match the destination
parameter prior to rewriting them with data from ldap. This allows to
automatically remove the keys of users that are no longer in LDAP.

If a variables `{ldap:uid}` is used in the destination, it is replaced with a
wildcard `*` and target files are globbed from the destination string.

If the destination contains a mix of files managed manually and by userplex, you
may want to prevent userplex from removing files it doesn't manage. This can be
done using a deletion marker, which tells userplex that it created the file and
thus is allowed to delete it if needed. The configuration is trivial: just set
the `deletionmarker` parameter to a unique string.

```yaml
modules:
    # regular users that need their keys in puppet
    - name: authorizedkeys
      ldapgroups:
        - myadmins
        - mydevelopers
        - myqa
      create: true
      delete: true
      parameters:
          destination: /data/puppet-config/users/modules/users/files/{ldap:uid}/.ssh/authorized_keys
          # if present, userplex will only delete files that contain the marker
          deletionmarker: userplex_all

    # members of svcops have their keys in the root authorized_keys
    - name: authorizedkeys
      ldapgroups:
        - myadmins
      create: true
      delete: false
      parameters:
          destination: /data/puppet-config/users/modules/users/files/root/.ssh/authorized_keys
```
Userplex will leave the authorized_keys file of user `root`, and any other
manually managed file, untouched because they will not contain the deletion
marker.
