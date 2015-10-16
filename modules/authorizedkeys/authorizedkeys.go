package authorizedkeys

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/mozilla-services/userplex/modules"
)

func init() {
	modules.Register("authorizedkeys", new(module))
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
}

type parameters struct {
	Destination string
}

func (r *run) Run() (err error) {
	var params parameters
	err = r.Conf.GetParameters(&params)
	if err != nil {
		return err
	}
	users, err := r.Conf.LdapCli.GetUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		log.Fatal(err)
	}
	userkeys := make(map[string][]string)
	destfiles := make(map[string]*os.File)
	// First gather all the uid and ssh pubkeys from ldap
	for _, user := range users {
		// extract the shortdn from 'mail=bob@mozilla.com,ou=people,dc=mozilla'
		shortdn := strings.Split(user, ",")[0]
		uid, err := r.Conf.LdapCli.GetUserId(shortdn)
		if err != nil {
			log.Printf("[warning] authorizedkeys: %v", err)
			continue
		}
		userkeys[uid], err = r.Conf.LdapCli.GetUserSSHPublicKeys(shortdn)
		if err != nil {
			log.Printf("[warning] authorizedkeys: %v", err)
			continue
		}
		log.Printf("[info] found %d keys for user %s", len(userkeys[uid]), uid)

	}
	// Second open once file descriptor per destination
	for uid, _ := range userkeys {
		dest := strings.Replace(params.Destination, "{ldap:uid}", uid, -1)
		if _, ok := destfiles[dest]; !ok {
			if r.Conf.DryRun {
				log.Println("[dryrun] would have created", dest)
				continue
			}
			destfiles[dest], err = os.Create(dest)
			if err != nil {
				log.Printf("[warning] can't create %s: %v", dest, err)
			}
			defer destfiles[dest].Close()
		}
	}
	// Finally, write the pubkeys in the destfiles
	for uid, keys := range userkeys {
		dest := strings.Replace(params.Destination, "{ldap:uid}", uid, -1)
		fmt.Fprintf(destfiles[dest], "# %s LDAP pubkeys\n", uid)
		for _, key := range keys {
			if r.Conf.DryRun {
				log.Printf("[dryrun] would have written pubkey of %s into %s", uid, dest)
				continue
			}
			fmt.Fprintf(destfiles[dest], "%s\n", key)
		}
	}
	return
}
