package authorizedkeys

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	// Gather all the uid and ssh pubkeys from ldap
	userkeys := r.getUserKeys(users)

	// Open one file descriptor per destination
	destfiles := r.openDestFiles(params.Destination, userkeys)
	defer func() {
		for dest, _ := range destfiles {
			destfiles[dest].Close()
		}
	}()

	// Write the pubkeys in the destfiles
	r.writePubKeys(params.Destination, userkeys, destfiles)
	return
}

func (r *run) getUserKeys(users []string) (userkeys map[string][]string) {
	userkeys = make(map[string][]string)
	for _, user := range users {
		// extract the shortdn from 'mail=bob@mozilla.com,ou=people,dc=mozilla'
		shortdn := strings.Split(user, ",")[0]
		uid, err := r.Conf.LdapCli.GetUserId(shortdn)
		if err != nil {
			log.Printf("[warning] authorizedkeys: %v", err)
			continue
		}
		for _, mapping := range r.Conf.UidMap {
			if mapping.LdapUid == uid {
				uid = mapping.UsedUid
			}
		}
		userkeys[uid], err = r.Conf.LdapCli.GetUserSSHPublicKeys(shortdn)
		if err != nil {
			log.Printf("[warning] authorizedkeys: %v", err)
			continue
		}
		log.Printf("[info] found %d keys for user %s", len(userkeys[uid]), uid)

	}
	return
}

func (r *run) openDestFiles(d string, userkeys map[string][]string) (destfiles map[string]*os.File) {
	var err error
	destfiles = make(map[string]*os.File)
	for uid, _ := range userkeys {
		dest := strings.Replace(d, "{ldap:uid}", uid, -1)
		if _, ok := destfiles[dest]; !ok {
			if r.Conf.DryRun {
				log.Println("[dryrun] would have created", dest)
				continue
			}
			os.MkdirAll(filepath.Dir(dest), 0750)
			destfiles[dest], err = os.Create(dest)
			if err != nil {
				log.Printf("[warning] can't create %s: %v", dest, err)
			}
		}
	}
	return
}

func (r *run) writePubKeys(d string, userkeys map[string][]string, destfiles map[string]*os.File) {
	for uid, keys := range userkeys {
		dest := strings.Replace(d, "{ldap:uid}", uid, -1)
		fmt.Fprintf(destfiles[dest], "# %s LDAP pubkeys\n", uid)
		if len(keys) == 0 {
			fmt.Fprintf(destfiles[dest], "# no key found in ldap, ask user to add one\n")
			continue
		}
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
