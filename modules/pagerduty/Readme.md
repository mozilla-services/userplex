## PagerDuty Module

This module creates and deletes users from PagerDuty based on LDAP groups. Users are notified via email about their account creation/deletion via unencrypted `userplex` email. There are no secrets sent to users via this email.

### Configuration

Parameters:
  - Subdomain: the subdomain of PagerDuty that your account uses, used for differentiating between PagerDuty accounts
Credentials:
  - APIKey: your PagerDuty API key

NOTE: the uidmap for the PagerDuty module maps LDAP _emails_ to PagerDuty _emails_, _not_ user IDs.

### Configuration Example

`-   name: pagerduty
        ldapgroups:
        -   ops
        create: true
        delete: true
        notify:
            mode: smtp
            recipient: '{ldap:mail}'
        parameters:
            subdomain: ops-pd
        credentials:
            apikey: 018jafajkf
        uidmap:
        -   ldapuid: foo@bar.com
            localuid: foobar@bar.com`
