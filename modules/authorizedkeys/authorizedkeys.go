package authorizedkeys

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.mozilla.org/userplex/modules"
	"go.mozilla.org/userplex/notifications"

	"go.mozilla.org/person-api"

	log "github.com/sirupsen/logrus"
)

type AuthorizedKeysModule struct {
	*modules.BaseModule
	config *modules.AuthorizedKeysConfiguration
}

func (akm *AuthorizedKeysModule) NewFromInterface(config modules.Configuration, notificationsConfig notifications.Config, PersonClient *person_api.Client) modules.Module {
	return New(config.(modules.AuthorizedKeysConfiguration), notificationsConfig, PersonClient)
}

func New(c modules.AuthorizedKeysConfiguration, notificationsConfig notifications.Config, PersonClient *person_api.Client) *AuthorizedKeysModule {
	akm := &AuthorizedKeysModule{config: &c, BaseModule: &modules.BaseModule{Notifications: notificationsConfig, PersonClient: PersonClient}}
	return akm
}

func (akm *AuthorizedKeysModule) hasAllowedGroup(person *person_api.Person) bool {
	for group := range person.AccessInformation.LDAP.Values {
		for _, configuredGroup := range akm.config.LdapGroups {
			if group == configuredGroup {
				return true
			}
		}
	}
	return false
}

func (akm *AuthorizedKeysModule) Create(username string, person *person_api.Person) error {
	if !akm.hasAllowedGroup(person) {
		return fmt.Errorf("user %s does not have one of the allowed LDAP groups (%v)", username, akm.config.LdapGroups)
	}

	localUsername := akm.LDAPUsernameToLocalUsername(username, akm.config.UsernameMap)
	dest, err := interpolate(akm.config.Path, localUsername)
	if err != nil {
		return err
	}

	log.Infof("Adding user %s to %s", localUsername, dest)

	os.MkdirAll(filepath.Dir(dest), 0750)
	destfile, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Errorf("can't create %q: %v", dest, err)
		return err
	}
	log.Infof("creating %q", dest)

	scanner := bufio.NewScanner(destfile)
	fileContents := []string{}
	for scanner.Scan() {
		fileContents = append(fileContents, scanner.Text())
	}

	keys := person.GetSSHPublicKeys()
	sort.Strings(keys)
	for _, key := range keys {
		exists := false
		for _, line := range fileContents {
			if key == line {
				exists = true
				break
			}
		}

		if exists {
			continue
		}

		// Write or append to file
		fmt.Fprintf(destfile, "%s\n", key)
	}
	log.Infof("%d keys written into %q", len(keys), dest)

	return destfile.Close()
}

func (akm *AuthorizedKeysModule) Reset(username string, person *person_api.Person) error {
	return fmt.Errorf("Reset not supported by Authorized Keys module.")
}

func (akm *AuthorizedKeysModule) Delete(username string) error {
	localUsername := akm.LDAPUsernameToLocalUsername(username, akm.config.UsernameMap)
	file, err := interpolate(akm.config.Path, localUsername)
	if err != nil {
		return err
	}
	log.Infof("removing %q", file)
	err = os.Remove(file)
	if err != nil {
		log.Errorf("failed to remove %q: %v", file, err)
		return err
	}
	return nil
}

func (akm *AuthorizedKeysModule) Sync() error {
	return fmt.Errorf("Sync not supported by Authorized Keys module.")
}

func (akm *AuthorizedKeysModule) Verify() error {
	badPaths, err := akm.verifyPaths()
	if err != nil {
		return err
	}
	if badPaths == nil {
		return nil
	}

	for _, path := range badPaths {
		fmt.Printf("%s has no matching person entry in the Person API", path)
	}

	return nil
}

func (akm *AuthorizedKeysModule) verifyPaths() ([]string, error) {
	if !strings.Contains(akm.config.Path, "{username}") {
		log.Warnf("Authorized Keys 'verify' does not operate on paths without '{username}'. Skipping %s", akm.config.Path)
		return nil, nil
	}

	globber, err := interpolate(akm.config.Path, "*")
	if err != nil {
		return nil, err
	}
	files, err := filepath.Glob(globber)
	if err != nil {
		return nil, err
	}
	fileMap := map[string]bool{}
	for _, f := range files {
		fileMap[f] = true
	}

	// TODO: Filter to just employees
	allLdapUsers, err := akm.PersonClient.GetAllUsers()
	if err != nil {
		log.Errorf("Error getting users from Person API: %s", err)
		return nil, err
	}

	for _, person := range allLdapUsers {
		if akm.hasAllowedGroup(person) {
			personPath, err := interpolate(akm.config.Path, akm.LDAPUsernameToLocalUsername(person.GetLDAPUsername(), akm.config.UsernameMap))
			if err != nil {
				log.Errorf("Error interpolating person's (%s) file path.", person.GetLDAPUsername())
				return nil, err
			}
			fileMap[personPath] = false
		}
	}

	badPaths := []string{}
	for filePath, notInLdap := range fileMap {
		if !notInLdap {
			badPaths = append(badPaths, filePath)
		}
	}

	return badPaths, nil
}

func interpolate(orig, uid string) (string, error) {
	prevstart := 0
	for {
		savedstr := orig[:prevstart]
		substr := orig[prevstart:]
		start := strings.Index(substr, "{")
		stop := strings.Index(substr, "}")
		if start < 0 || stop < 0 || stop < start {
			break
		}
		comp := strings.Split(substr[start+1:stop], ":")
		if comp[0] != "username" && comp[0] != "env" {
			err := fmt.Errorf("invalid interpolation variable %s, expected 'username' or 'env:<value>'", substr[start+1:stop])
			return "", err
		}
		var replacement string
		switch comp[0] {
		case "username":
			replacement = uid
		case "env":
			replacement = os.Getenv(comp[1])
			if replacement == "" {
				return "", fmt.Errorf("$%s expected to be set.", comp[1])
			}
		}
		orig = savedstr + substr[:start] + replacement + substr[stop+1:]
		prevstart = stop + 1
	}
	return orig, nil
}
