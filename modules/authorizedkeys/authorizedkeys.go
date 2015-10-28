// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>
package authorizedkeys

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	p    parameters
}

type parameters struct {
	Destination    string
	DeletionMarker string
}

func (r *run) Run() (err error) {
	err = r.Conf.GetParameters(&r.p)
	if err != nil {
		return err
	}
	users, err := r.Conf.LdapCli.GetUsersInGroups(r.Conf.LdapGroups)
	if err != nil {
		log.Fatal(err)
	}
	// Gather all the uid and ssh pubkeys from ldap
	userkeys := r.getUserKeys(users)

	// If delete is set, flush existing files that match the deletionmarker
	// (or all files that match if no marker is defined). The files will be
	// recreate in the next step
	err = r.deleteMarkedFiles()
	if err != nil {
		return
	}

	// Open one file descriptor per destination
	destfiles := r.openDestFiles(userkeys)
	defer func() {
		for dest, _ := range destfiles {
			destfiles[dest].Close()
		}
	}()

	// Write the pubkeys in the destfiles
	r.writePubKeys(userkeys, destfiles)
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
		// apply the uid map: only store the translated uid in the userkeys
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
		log.Printf("[info] found %d keys for user %q", len(userkeys[uid]), uid)

	}
	return
}

func (r *run) deleteMarkedFiles() (err error) {
	if !r.Conf.Delete {
		return
	}
	globber := strings.Replace(r.p.Destination, "{ldap:uid}", "*", -1)
	files, err := filepath.Glob(globber)
	if err != nil {
		return
	}
	for _, file := range files {
		fd, err := os.Open(file)
		if err != nil {
			log.Printf("[error] can't open %q for reading, skipping it", file)
		}
		defer fd.Close()
		scanner := bufio.NewScanner(fd)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "deletionmarker="+r.p.DeletionMarker) {
				if r.Conf.DryRun {
					log.Printf("[dryrun] would have deleted %q", file)
					continue
				}
				log.Printf("[info] flushing %q", file)
				err = os.Remove(file)
				if err != nil {
					log.Printf("[error] failed to remove %q: %v", file, err)
				}
				continue
			}
		}
	}
	return
}

func (r *run) openDestFiles(userkeys map[string][]string) (destfiles map[string]*os.File) {
	var err error
	destfiles = make(map[string]*os.File)
	for uid, _ := range userkeys {
		dest := strings.Replace(r.p.Destination, "{ldap:uid}", uid, -1)
		if _, ok := destfiles[dest]; !ok {
			if r.Conf.DryRun {
				log.Println("[dryrun] would have created", dest)
				continue
			}
			os.MkdirAll(filepath.Dir(dest), 0750)
			destfiles[dest], err = os.Create(dest)
			if err != nil {
				log.Printf("[warning] can't create %q: %v", dest, err)
			}
			log.Printf("[info] creating %q", dest)
		}
	}
	return
}

func (r *run) writePubKeys(userkeys map[string][]string, destfiles map[string]*os.File) {
	var uids []string
	for uid, _ := range userkeys {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		dest := strings.Replace(r.p.Destination, "{ldap:uid}", uid, -1)
		if r.Conf.DryRun {
			log.Printf("[dryrun] would have written pubkey of %q into %q", uid, dest)
			continue
		}
		marker := ""
		if r.p.DeletionMarker != "" {
			marker = fmt.Sprintf("; deletionmarker=%s", r.p.DeletionMarker)
		}
		fmt.Fprintf(destfiles[dest], "# %s LDAP pubkeys%s\n", uid, marker)
		if len(userkeys[uid]) == 0 {
			fmt.Fprintf(destfiles[dest], "# no key found in ldap, ask user to add one\n")
			continue
		}
		var keys []string
		for _, key := range userkeys[uid] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(destfiles[dest], "%s\n", key)
		}
		log.Printf("[info] %d keys written into %q", len(userkeys[uid]), dest)
	}
	return
}
