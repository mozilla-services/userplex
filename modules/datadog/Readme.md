Datadog
=======
This is a prototype module that isn't yet functional. It will invite members of
a LDAP group to join datadog, but due to a limitation in the datadog api,
invitations will be sent **every time** the script runs, which is obviously not
an acceptable behavior.

Credentials
-----------

```yaml
modules:
    - name: datadog
      credentials:
        apikey: fffffffffffff
        appkey: foobar32xxxxxx
```
