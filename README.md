# Userplex [![GoDoc](https://godoc.org/go.mozilla.org/userplex?status.svg)](https://godoc.org/go.mozilla.org/userplex) [![Build Status](https://travis-ci.org/mozilla-services/userplex.svg)](https://travis-ci.org/mozilla-services/userplex)

Propagate users from Mozilla's [Person API](https://github.com/mozilla-iam/cis/blob/master/docs/PersonAPI.md) to third party systems.

## Installation

If you have Go v1.13+ installed, you can install userplex by running:

```bash
$ go get go.mozilla.org/userplex
```

Otherwise, you can get a binary from the [releases section](https://github.com/mozilla-services/userplex/releases).

## Configuration

You find an example configuration file in the repo at [`config.yaml`](https://github.com/mozilla-services/userplex/blob/master/config.yaml)


```yaml
# Configuration for using Mozilla's Person API
# https://github.com/mozilla-iam/cis/blob/master/docs/PersonAPI.md
person:
  person_client_id: "client_id"
  person_client_secret: "client_secret"
  person_base_url: "https://person_url.com"
  person_auth0_url: "https://auth0.com"

# Configuration for sending notifications. Will only be used
# if the module block has `notify_new_users` set to `true`.
notifications:
    email:
        # your smtp relay may require authentication (AWS SES does), so make
        # sure to set the parameters below to an authorized sender
        host: "email-smtp.us-east-1.amazonaws.com"
        port: 587
        from: "myauthorizedsender@example.net"
        cc:   "bob.kelso@gmail.com"
        replyto: "Something <something@example.com>"
        auth:
            user: "AKIAI3TZL"
            pass: "AoXAy......"


# AWS Module configuration section.
#
# You may have multiple AWS accounts configured and all will
# be operated on. The way to give different permissions based
# on the account is to use the `group_mapping` to give
# different ldap groups different AWS groups. As well, if you do
# not have a `default` in `group_mapping`, a user without a
# matching group will just get ignored.
aws:
  - account_name: "myawsaccount"
    notify_new_users: true
    credentials:
        # if blank, will use the default aws credential flow
        accesskey: AKIAnnnn
        secretkey: XXXXXXX
    # Used to translate ldap usernames into "local usernames"
    # which will be used as the username in AWS (or which ever
    # module they are present in)
    username_map:
      - ldap_username: bkelso
        local_username: bob
      - ldap_username: tanderson
        local_username: neo
    group_mapping:
      - ldap_group: "sysadmins"
        iam_groups:
          - ldapmanaged
          - admin
      - ldap_group: "developers"
        iam_groups:
          - ldapmanaged
          - dev_only
      - default: true
        iam_groups:
          - ldapmanaged

# Authorized Keys Module configuration section.
#
# As with the AWS Module section, you can have multiple
# authorized keys paths configured. The core
# configuration here is the list of allowed `ldap_groups`
# and how the `path` is setup. You can use `{username}`
# or `{env:<ENV_VAR>}` within the path.
authorized_keys:
    - name: all_authorizedkeys
      # Used to translate ldap usernames into "local usernames"
      # which will be used as the username in authorized keys
      # (or which ever module they are present in)
      username_map:
        - ldap_username: bkelso
          local_username: bob
        - ldap_username: tanderson
          local_username: neo
      ldap_groups:
        - sysadmins
        - developers
        - devssh
      # {username} will be replaced with the primary username for the user being created
      path: /data/puppet/modules/users/files/{username}/.ssh/authorized_keys
      # {env:ROOT_DIR} will be replaced with the env var $ROOT_DIR
      # path: /data/puppet/modules/users/files/{env:ROOT_DIR}/.ssh/authorized_keys

    - name: root_authorizedkeys
      ldap_groups:
        - sysadmins
      # Used to translate ldap usernames into "local usernames"
      # which will be used as the username in authorized keys
      # (or which ever module they are present in)
      username_map:
        - ldap_username: tanderson
          local_username: neo
      path: /data/puppet/modules/users/files/root/.ssh/authorized_keys
```

## Usage

```
NAME:
   userplex - Propagate users from Mozilla's Person API to third party systems.

USAGE:
   userplex [global options] command [command options] [arguments...]

VERSION:
   v1.0.0

AUTHORS:
   AJ Bahnken <ajvb@mozilla.com>
   Julien Vehent <jvehent@mozilla.com>

COMMANDS:
   aws             Operations within AWS
   authorizedkeys  Operations within authorizedkeys files
   get-person      Get Person from Person API. Useful for finding the correct identifier
   help, h         Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config value, -c value  Path to userplex config file [$USERPLEX_CONFIG_PATH]
   --help, -h                show help
   --version, -v             print the version
```

#### AWS Usage

```
$ userplex -c config-encrypted.yaml aws help
NAME:
   userplex aws - Operations within AWS

USAGE:
   userplex aws [global options] command [command options] [arguments...]

VERSION:
   v1.0.0

COMMANDS:
   create  Create user
   reset   Reset user credentials
   delete  Delete user
   sync    Run sync operation
   verify  Verify users against Person API. Outputs report, use `sync` to fix discrepancies.

GLOBAL OPTIONS:
   --help, -h  show help

$ userplex -c config-encrypted.yaml aws create example-user@mozilla.com
INFO[0001] aws "example-aws-account": user "example-user" not found, needs to be created 
Notify new users disabled, printing output.
Created new user: example-user
....

$ userplex -c config-encrypted.yaml aws delete example-user@mozilla.com
INFO[0002] aws "example-aws-account": deleted user "example-user"

$ userplex -c config-encrypted.yaml aws verify
Users not in LDAP:
  * test-user

$ userplex -c config-encrypted.yaml aws sync
Users not in LDAP:
  * test-user
Would you like to remove these users from the example-aws-account AWS account?
  * test-user
(y/n): y
```

#### Authorized Keys Usage

```
$ userplex -c config-encrypted.yaml authorizedkeys help
NAME:
   userplex authorizedkeys - Operations within authorizedkeys files

USAGE:
   userplex authorizedkeys [global options] command [command options] [arguments...]

VERSION:
   v1.0.0

COMMANDS:
   create  Create user
   reset   Reset user credentials
   delete  Delete user
   sync    Run sync operation
   verify  Verify users against Person API. Outputs report, use `sync` to fix discrepancies.

GLOBAL OPTIONS:
   --help, -h  show help

$ userplex -c config-encrypted.yaml authorizedkeys create example-user@mozilla.com
INFO[0000] Adding user example-user to /puppet/userplex-testing/ak/example-user/.ssh/authorized_keys
INFO[0000] creating "/puppet/userplex-testing/ak/example-user/.ssh/authorized_keys"
INFO[0000] 1 keys written into "/puppet/userplex-testing/ak/example-user/.ssh/authorized_keys"
INFO[0000] Adding user example-user to /puppet/userplex-testing/ak/root/.ssh/authorized_keys
INFO[0000] creating "/puppet/userplex-testing/ak/root/.ssh/authorized_keys"
INFO[0000] 1 keys written into "/puppet/userplex-testing/ak/root/.ssh/authorized_keys"

$ cat /puppet/userplex-testing/ak/example-user/.ssh/authorized_keys
ssh-rsa AAAAB3.... example-user@mozilla

$ userplex -c config-encrypted.yaml authorizedkeys delete example-user@mozilla.com
INFO[0000] removing "/puppet/userplex-testing/ak/example-user/.ssh/authorized_keys"
INFO[0000] removing "/puppet/userplex-testing/ak/root/.ssh/authorized_keys"

$ cat /puppet/userplex-testing/ak/example-user/.ssh/authorized_keys
cat: /puppet/userplex-testing/ak/example-user/.ssh/authorized_keys: No such file or directory

```


## License
Mozilla Public License 2.0

## Authors
  * AJ Bahnken <ajvb@mozilla.com>
  * Julien Vehent <ulfr@mozilla.com>
