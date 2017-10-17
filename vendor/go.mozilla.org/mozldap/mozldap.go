package mozldap // import "go.mozilla.org/mozldap"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/ldap.v2"
)

type Client struct {
	conn        *ldap.Conn
	Host        string
	Port        int
	UseTLS      bool
	UseStartTLS bool
	BaseDN      string
}

// Close the LDAP connection
func (cli *Client) Close() {
	cli.conn.Close()
}

// NewClient initializes a ldap connection to a given URI. if tlsconf is nil, sane
// default are used (tls1.2, secure verify, ...).
//
// * uri is a connection string to the ldap server, eg. `ldaps://example.net:636/dc=example,dc=net`
//
// * username is a bind user, eg. `uid=bind-bob,ou=logins,dc=mozilla`
//
// * password is a password for the bind user
//
// * cacertpath is the path to a file containing trusted root certificates
//
// * tlsconf is a Go TLS Configuration
//
// * starttls requires that the LDAP connection is opened insecurely but immediately switched to TLS using the StartTLS protocol.
func NewClient(uri, username, password string, tlsconf *tls.Config, starttls bool) (Client, error) {
	errorPrefix := fmt.Sprintf("mozldap.NewClient(uri=%q, username=%q, password=****, starttls=%v)",
		uri, username, starttls)

	cli, err := ParseUri(uri)
	if err != nil {
		return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
	}
	if tlsconf == nil {
		// sensible default for TLS configuration
		tlsconf = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			InsecureSkipVerify: false,
			ServerName:         cli.Host,
		}
	}
	// if we're secure, we want to check that
	// the server name matches the uri hostname
	if !tlsconf.InsecureSkipVerify && tlsconf.ServerName == "" {
		tlsconf.ServerName = cli.Host
	}
	if cli.UseTLS {
		cli.conn, err = ldap.DialTLS("tcp",
			fmt.Sprintf("%s:%d", cli.Host, cli.Port),
			tlsconf)
	} else {
		cli.conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", cli.Host, cli.Port))
	}
	if err != nil {
		return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
	}
	// TLS and StartTLS are mutually exclusive
	if !cli.UseTLS && starttls {
		cli.UseStartTLS = true
		err = cli.conn.StartTLS(tlsconf)
		if err != nil {
			cli.Close()
			return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
		}
	}
	// First bind with a read only user
	err = cli.conn.Bind(username, password)
	if err != nil {
		cli.Close()
		return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
	}
	return cli, err
}

// NewTLSClient initializes a ldap connection to a given URI using a client certificate.
// This mode does not use StartTLS, and enforces a TLS connection before the LDAP authentication happens.
//
// * uri is a connection string to the ldap server, eg. `ldaps://example.net:636/dc=example,dc=net`
//
// * username is a bind user, eg. `uid=bind-bob,ou=logins,dc=mozilla`
//
// * password is a password for the bind user
//
// * tlscertpath is the path to a X509 client certificate in PEM format, eg `/etc/mozldap/client.crt`
//
// * tlskeypath is the path to the private key that maps to the client certificate, eg `/etc/mozldap/client.key`
//
// * cacertpath is the path to the X509 certificate of the Certificate Authority.
//
// * tlsconf is a Go TLS Configuration which can be used to disable cert verification and other horrors
func NewTLSClient(uri, username, password, tlscertpath, tlskeypath, cacertpath string, tlsconf *tls.Config) (Client, error) {
	errorPrefix := fmt.Sprintf("mozldap.NewTLSClient(uri=%q, username=%q, password=****, tlscertpath=%q, tlskeypath=%q, cacertpath=%q)", uri, username, tlscertpath, tlskeypath, cacertpath)
	cli := Client{}

	// import the client certificates
	cert, err := tls.LoadX509KeyPair(tlscertpath, tlskeypath)
	if err != nil {
		return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
	}

	if tlsconf == nil {
		// sensible default for TLS configuration
		tlsconf = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			InsecureSkipVerify: false,
			// TODO: this is an empty string!
			ServerName: cli.Host,
		}
	}
	if cacertpath != "" {
		// import the ca cert
		ca := x509.NewCertPool()
		CAcert, err := ioutil.ReadFile(cacertpath)
		if err != nil {
			return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
		}
		if ok := ca.AppendCertsFromPEM(CAcert); !ok {
			return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
		}
		tlsconf.RootCAs = ca
	}
	tlsconf.Certificates = []tls.Certificate{cert}
	// instantiate an ldap client
	cli, err = NewClient(uri, username, password, tlsconf, false)
	if err != nil {
		return Client{}, fmt.Errorf("%s -> %s", errorPrefix, err.Error())
	}
	return cli, err
}

// format: ldaps://example.net:636/dc=example,dc=net
const URIRE = "ldap(s)?://([^:]+):?([0-9]{1,5})?/(.+)"
const URIFORMAT = "ldaps://ldap.example.net:636/dc=example,dc=net"

// ParseUri extracts connection parameters from a given URI and return a client
// that is ready to connect. This shouldn't be called directly, use NewClient() instead.
func ParseUri(uri string) (Client, error) {
	errorPrefix := fmt.Sprintf("mozldap.ParseUri(uri=%q)", uri)

	cli := Client{}

	urire := regexp.MustCompile(URIRE)
	fields := urire.FindStringSubmatch(uri)
	if fields == nil || len(fields) != 5 {
		return Client{}, fmt.Errorf("%s -> failed to parse URI. Format: %q", errorPrefix, URIFORMAT)
	}

	// tls or not depends on "s"
	if fields[1] == "s" {
		cli.UseTLS = true
	}
	// get the hostname
	if fields[2] == "" {
		return Client{}, fmt.Errorf("%s -> missing host in URI. Format: %q", errorPrefix, URIFORMAT)
	}
	cli.Host = fields[2]
	// get the port or use default ports
	if fields[3] == "" {
		if cli.UseTLS {
			cli.Port = 636
		} else {
			cli.Port = 389
		}
	} else {
		port, err := strconv.Atoi(fields[3])
		if err != nil {
			return Client{}, fmt.Errorf("%s -> invalid port in URI. Format: %q", errorPrefix, URIFORMAT)
		}
		cli.Port = port
	}
	// get the base DN
	if fields[4] == "" {
		return Client{}, fmt.Errorf("%s -> missing BaseDN in URI. Format: %q", errorPrefix, URIFORMAT)
	}
	cli.BaseDN = fields[4]
	return cli, nil
}

// Search runs a search query against the entire subtree of the LDAP base DN
func (cli *Client) Search(base, filter string, attributes []string) ([]ldap.Entry, error) {
	// empty
	entries := []ldap.Entry{}

	// default BaseDN
	if base == "" {
		base = cli.BaseDN
	}
	searchRequest := ldap.NewSearchRequest(
		cli.BaseDN,             // base dn
		ldap.ScopeWholeSubtree, // scope
		ldap.NeverDerefAliases, // deref aliases
		0,          // size limit
		0,          // time limit
		false,      // types only
		filter,     // search filter
		attributes, // return attributes
		nil)        // controls
	searchResult, err := cli.conn.Search(searchRequest)
	if err != nil {
		return entries, fmt.Errorf("mozldap.Search(base=%q, filter=%q, attributes=%q) -> %v",
			base, filter, attributes, err)
	}
	for _, entry := range searchResult.Entries {
		entries = append(entries, *entry)
	}
	return entries, nil
}

// GetUserId exists for API compatiability (use GetUserUID)
func (cli *Client) GetUserId(shortdn string) (string, error) {
	return cli.GetUserUID(shortdn)
}

// GetUserUID returns the uid of a given user
//
// example: cli.GetUserUID("mail=jvehent@mozilla.com")
func (cli *Client) GetUserUID(shortdn string) (string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserUID(shortdn=%q)", shortdn)
	uid := ""

	entries, err := cli.Search("", "("+shortdn+")", []string{"uid"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching shortdn %q, expected 1", errorPrefix, len(entries), shortdn)
	}
	uid = entries[0].GetAttributeValue("uid")
	if uid == "" {
		return "", fmt.Errorf("%s -> could not find uid for shortdn %q", errorPrefix, shortdn)
	}
	return uid, nil
}

// GetUserFullNameByEmail returns the distinguished name of a given user using his ID
//
// example: cli.GetUserFullNameByEmail("jvehent@mozilla.com")
func (cli *Client) GetUserFullNameByEmail(email string) (string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserFullNameByEmail(mail=%q)", email)
	fullName := ""

	entries, err := cli.Search("", "(mail="+email+")", []string{"cn"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching mail %q, expected 1", errorPrefix, len(entries), email)
	}
	fullName = entries[0].GetAttributeValue("cn")
	if fullName == "" {
		return "", fmt.Errorf("%s -> could not find fullName for user %q", errorPrefix, email)
	}
	return fullName, err
}

// GetUserDNById exists for API compatiability (use GetUserDNByUID)
func (cli *Client) GetUserDNById(uid string) (string, error) {
	return cli.GetUserDNByUID(uid)
}

// GetUserDNByUID returns the distinguished name of a given user using his ID
//
// example: cli.GetUserDNByUID("jvehent")
func (cli *Client) GetUserDNByUID(uid string) (string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserDNByUID(uid=%q)", uid)
	dn := ""

	entries, err := cli.Search("", "(uid="+uid+")", []string{"mail"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching uid %q, expected 1", errorPrefix, len(entries), uid)
	}
	dn = entries[0].DN
	if dn == "" {
		return "", fmt.Errorf("%s -> could not find DN for uid %q", errorPrefix, uid)
	}
	return dn, nil
}

// GetUserUidNumber exists for API compatiability (use GetUserUIDNumber)
func (cli *Client) GetUserUidNumber(shortdn string) (uint64, error) {
	return cli.GetUserUIDNumber(shortdn)
}

// GetUserUIDNumber returns the UID number of a user using a shortdn
//
// example: cli.GetUserUIDNumber("mail=jvehent@mozilla.com")
func (cli *Client) GetUserUIDNumber(shortdn string) (uint64, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserUIDNumber(shortdn=%q)", shortdn)
	uidNumber := uint64(0)

	entries, err := cli.Search("", "("+shortdn+")", []string{"uidNumber"})
	if err != nil {
		return 0, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return 0, fmt.Errorf("%s -> found %d entries matching shortdn %q, expected 1", errorPrefix, len(entries), shortdn)
	}
	uidNumber, err = strconv.ParseUint(entries[0].GetAttributeValue("uidNumber"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}

	if uidNumber < 0 {
		return 0, fmt.Errorf("%s -> could not find uidNumber for %q", errorPrefix, shortdn)
	}
	return uidNumber, err
}

// GetUserGithubByUID returns the Github username of a given user using their ID
// example: cli.GetUserGithubByUID("jvehent")
func (cli *Client) GetUserGithubByUID(uid string) (string, error) {
	errorText := fmt.Sprintf("mozldap.GetUserDNByUID(uid=%q)", uid)
	githubUsername := ""

	entries, err := cli.Search("", "(uid="+uid+")", []string{"githubProfile"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorText, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching uid %q, expected 1", errorText, len(entries), uid)
	}

	githubUsername = entries[0].GetAttributeValue("githubProfile")
	if githubUsername == "" {
		return "", fmt.Errorf("%s -> could not find githubProfile for %q", errorText, uid)
	}

	return githubUsername, nil
}

// GetUserSSHPublicKeys returns a list of public keys defined in a user's sshPublicKey
// LDAP attribute. If no public key is found, the list is empty.
//
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
//
// example: cli.GetUserSSHPublicKeys("mail=jvehent@mozilla.com")
func (cli *Client) GetUserSSHPublicKeys(shortdn string) ([]string, error) {
	pubkeys := []string{}

	entries, err := cli.Search("", "("+shortdn+")", []string{"sshPublicKey"})
	if err != nil {
		return []string{}, fmt.Errorf("mozldap.GetUserSSHPublicKeys(shortdn=%q) -> %q", shortdn, err.Error())
	}
	for _, entry := range entries {
		keys := entry.GetAttributeValues("sshPublicKey")
		for _, key := range keys {
			if len(key) < 10 || key[0:3] != "ssh" {
				continue
			}
			pubkeys = append(pubkeys, strings.Trim(key, "\n"))
		}
	}
	return pubkeys, nil
}

// GetUserPGPFingerprint returns a PGP fingerprint for the user, or an error if no fingerprint is found.
//
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
//
// example: cli.GetUserPGPFingerprint("mail=jvehent@mozilla.com")
func (cli *Client) GetUserPGPFingerprint(shortdn string) (string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserPGPFingerprint(shortdn=%q)", shortdn)

	fingerprint := ""
	entries, err := cli.Search("", "("+shortdn+")", []string{"pgpFingerprint"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching shortdn %q, expected 1", errorPrefix, len(entries), shortdn)
	}
	fingerprint = entries[0].GetAttributeValue("pgpFingerprint")
	// remove spaces
	fingerprint = strings.Replace(fingerprint, " ", "", -1)
	if len(fingerprint) != 40 {
		return "", fmt.Errorf("%s -> could not find fingerprint for %q", errorPrefix, shortdn)
	}
	return fingerprint, err
}

// GetUserPGPKey returns a PGP public key for the user, or an error if no key is found.
// The fingerprint of the key is first search in LDAP, then used to find the public key
// on gpg.mozilla.org.
//
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
//
// example: cli.GetUserPGPKey("mail=jvehent@mozilla.com")
func (cli *Client) GetUserPGPKey(shortdn string) ([]byte, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserPGPKey(shortdn=%q)", shortdn)
	key := []byte{}

	fingerprint, err := cli.GetUserPGPFingerprint(shortdn)
	if err != nil {
		return []byte{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	re := regexp.MustCompile(`^0x[ABCDEF0-9]{8,64}$`)
	if !re.MatchString("0x" + fingerprint) {
		return []byte{}, fmt.Errorf("%s -> Invalid key id. Must be in format '0x[ABCDEF0-9]{8,64}", errorPrefix)
	}
	resp, err := http.Get("http://gpg.mozilla.org/pks/lookup?op=get&options=mr&search=0x" + fingerprint)
	if err != nil {
		return []byte{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return []byte{}, fmt.Errorf("%s -> keyserver lookup error: %q", errorPrefix, http.StatusText(resp.StatusCode))
	}
	key, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	return key, err
}

// GetUsersInGroups takes a list of ldap groups and returns a list of unique members
// that belong to at least one of the group. Duplicates are removed, so you only get
// members once even if they belong to several groups.
//
// example: cli.GetUsersInGroups([]string{"sysadmins", "svcops", "mojitomakers"})
func (cli *Client) GetUsersInGroups(groups []string) ([]string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUsersInGroups(groups=%q)", strings.Join(groups, ","))

	q := "(|"
	for _, group := range groups {
		q += "(cn=" + group + ")"
	}
	q += ")"
	entries, err := cli.Search("ou=groups,"+cli.BaseDN, q, []string{"member"})
	if err != nil {
		return []string{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	usersMap := make(map[string]bool)
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name == "member" {
				for _, val := range attr.Values {
					usersMap[val] = true
				}
			}
		}
	}

	users := []string{}
	for user := range usersMap {
		users = append(users, user)
	}
	return users, nil
}

// GetEnabledUsersInGroups takes a list of ldap groups and returns a list of unique members
// that belong to at least one of the group. Duplicates and disabled users are removed, so
// you only get members once even if they belong to several groups.
//
// example: cli.GetEnabledUsersInGroups([]string{"sysadmins", "svcops", "mojitomakers"})
func (cli *Client) GetEnabledUsersInGroups(groups []string) ([]string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetEnabledUsersInGroups(groups=%q)", strings.Join(groups, ","))

	usersInGroups, err := cli.GetUsersInGroups(groups)
	if err != nil {
		return []string{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	q := "(&(!(employeeType=DISABLED))(|"
	for _, userDN := range usersInGroups {
		q += "(" + strings.Split(userDN, ",")[0] + ")"
	}
	q += "))"
	entries, err := cli.Search(cli.BaseDN, q, []string{"DN"})
	if err != nil {
		return []string{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}

	enabledUsersMap := make(map[string]bool)
	for _, entry := range entries {
		enabledUsersMap[entry.DN] = true
	}

	enabledUsers := []string{}
	for user := range enabledUsersMap {
		enabledUsers = append(enabledUsers, user)
	}
	return enabledUsers, nil
}

// GetUserEmailByUid exists for compatiability (use GetUserEmailByUID)
func (cli *Client) GetUserEmailByUid(uid string) (string, error) {
	return cli.GetUserEmailByUID(uid)
}

// GetUserEmailByUID returns the first email address found in the user's attributes
//
// example: cli.GetUserEmailByUID("jvehent")
func (cli *Client) GetUserEmailByUID(uid string) (string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserEmailByUID(uid=%q)", uid)
	mail := ""

	entries, err := cli.Search("", "(uid="+uid+")", []string{"mail"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching uid %q, expected 1", errorPrefix, len(entries), uid)
	}
	if mails := entries[0].GetAttributeValues("mail"); len(mails) >= 1 {
		mail = mails[0]
	}
	if mail == "" {
		return "", fmt.Errorf("%s -> could not find email for %q", errorPrefix, uid)
	}
	return mail, err
}

// GetUserEmail returns the first email address found in the user's attributes
//
// example: cli.GetUserEmail("mail=jvehent@mozilla.com")
func (cli *Client) GetUserEmail(shortdn string) (string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetUserEmail(shortdn=%q)", shortdn)
	mail := ""

	entries, err := cli.Search("", "("+shortdn+")", []string{"mail"})
	if err != nil {
		return "", fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%s -> found %d entries matching shortdn %q, expected 1", errorPrefix, len(entries), shortdn)
	}
	if mails := entries[0].GetAttributeValues("mail"); len(mails) >= 1 {
		mail = mails[0]
	}
	if mail == "" {
		return "", fmt.Errorf("%s -> could not find email for %q", errorPrefix, shortdn)
	}
	return mail, err
}

// GetGroupsOfUser returns a list of groups a given user belongs to. This function returns the DN
// of all groups, including posix and scm groups.
//
// dn is the distinguished name of the user, such as "mail=jvehent@mozilla.com,o=com,dc=mozilla"
//
// example: cli.GetGroupsOfUser("mail=jvehent@mozilla.com,o=com,dc=mozilla")
func (cli *Client) GetGroupsOfUser(dn string) ([]string, error) {
	errorPrefix := fmt.Sprintf("mozldap.GetGroupsOfUser(dn=%q)", dn)
	groups := []string{}

	uid, err := cli.GetUserId(strings.Split(dn, ",")[0])
	if err != nil {
		return []string{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	mail, err := cli.GetUserEmail(strings.Split(dn, ",")[0])
	if err != nil {
		return []string{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	entries, err := cli.Search("ou=groups,"+cli.BaseDN, "(|(member="+dn+")(memberUID="+uid+")(memberUID="+mail+"))", []string{"DN"})
	if err != nil {
		return []string{}, fmt.Errorf("%s -> %q", errorPrefix, err.Error())
	}
	for _, entry := range entries {
		groups = append(groups, entry.DN)
	}
	return groups, err
}
