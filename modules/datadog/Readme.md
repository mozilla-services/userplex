Datadog
=======

This module invites users to join a given datadog account, and deletes existing
datadog users that are not members of the defined ldap groups.

```yaml
modules:
    - name: datadog
      ldapgroups:
        - mysysadmins
      create: true
      delete: true
      credentials:
        apikey: fffffffffffff
        appkey: foobar32xxxxxx
```

UID maps for this module must contain email addresses, since datadog uses email
as user handles.

```yaml
ddmap: &datadogmap1
    - ldapuid: bkelso@example.net
      useduid: bob@example.net

modules:
    - name: datadog
      uidmap: *datadogmap1
```
