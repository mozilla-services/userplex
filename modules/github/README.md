### Github

The Github userplex module audits users in organizations and correlates them with users in LDAP groups.

Features:
      - supports an `enforce2fa` boolean parameter that audits and removes users without 2FA if `delete` is enabled.
      - correlates LDAP users with Github usernames via the `ldapuid` <=> `localuid` mapping
            - identifies which teams users are in an organization, adds them to all teams listed in the config if they are members of the requisite LDAP groups- adds users to an organization if they are in the mapping regardless of teams specified if `create` is enabled
            - deletes these users from Github organizations if they are present, in `userplexteamname`, unaccounted for in LDAP, and `delete` is enabled
                  - Note: does NOT remove users from teams that are not represented in config (intentionally)

Config explanations:
      - credentials:
            - oauthtoken: a Github OAuth2 or Personal Access Token
      - parameters:
            - userplexteamname: the name of a team within your Github organization that has userplexed users
            - enforce2fa: enforces 2FA, removing users w/o it
            - organizations: a list of Github organizations for userplex to manage (supports multiple for the same set of LDAP users!)
                  - name: organization name on Github
                    teams: a list of teams to put matching LDAP users into within the organization
                        - teamname
                        - teamname2


`-   name: github
      ldapgroups:
      -   developers
      create: true
      notify:
          mode: smtp
          recipient: '{ldap:mail}'
      uidmap:
      -   ldapuid: foobar
          localuid: foo
      credentials:
          oauthtoken: 1982398notrealtoken
      parameters:
          enforce2fa: true
          userplexteamname: userplexed
          organization:
            name: my-org
            teams:
              -   userplexed
              -   test-team`
