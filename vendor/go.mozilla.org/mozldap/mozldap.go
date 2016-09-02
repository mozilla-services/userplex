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
func NewClient(uri, username, password string, tlsconf *tls.Config, starttls bool) (cli Client, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.NewClient(uri=%q, username=%q, password=****, starttls=%v) -> %v",
				uri, username, starttls, e)
		}
	}()
	cli, err = ParseUri(uri)
	if err != nil {
		panic(err)
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
		panic(err)
	}
	// TLS and StartTLS are mutually exclusive
	if !cli.UseTLS && starttls {
		cli.UseStartTLS = true
		err = cli.conn.StartTLS(tlsconf)
		if err != nil {
			cli.conn.Close()
			panic(err)
		}
	}
	// First bind with a read only user
	err = cli.conn.Bind(username, password)
	return
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
func NewTLSClient(uri, username, password, tlscertpath, tlskeypath, cacertpath string, tlsconf *tls.Config) (cli Client, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.NewTLSClient(uri=%q, username=%q, password=****, tlscertpath=%q, tlskeypath=%q, cacertpath=%q) -> %v",
				uri, username, tlscertpath, tlskeypath, cacertpath, e)
		}
	}()
	// import the client certificates
	cert, err := tls.LoadX509KeyPair(tlscertpath, tlskeypath)
	if err != nil {
		panic(err)
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
	if cacertpath != "" {
		// import the ca cert
		ca := x509.NewCertPool()
		CAcert, err := ioutil.ReadFile(cacertpath)
		if err != nil {
			panic(err)
		}
		if ok := ca.AppendCertsFromPEM(CAcert); !ok {
			panic("failed to import CA Certificate")
		}
		tlsconf.RootCAs = ca
	}
	tlsconf.Certificates = []tls.Certificate{cert}
	// instantiate an ldap client
	cli, err = NewClient(uri, username, password, tlsconf, false)
	if err != nil {
		panic(err)
	}
	return
}

// format: ldaps://example.net:636/dc=example,dc=net
const URIRE = "ldap(s)?://([^:]+):?([0-9]{1,5})?/(.+)"
const URIFORMAT = "ldaps://ldap.example.net:636/dc=example,dc=net"

// ParseUri extracts connection parameters from a given URI and return a client
// that is ready to connect. This shouldn't be called directly, use NewClient() instead.
func ParseUri(uri string) (cli Client, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.ParseUri(uri=%q) -> %v", uri, e)
		}
	}()
	urire := regexp.MustCompile(URIRE)
	fields := urire.FindStringSubmatch(uri)
	if fields == nil || len(fields) != 5 {
		panic("failed to parse URI. format is " + URIFORMAT)
	}

	// tls or not depends on "s"
	if fields[1] == "s" {
		cli.UseTLS = true
	}
	// get the hostname
	if fields[2] == "" {
		panic("missing host in URI. format is " + URIFORMAT)
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
		cli.Port, err = strconv.Atoi(fields[3])
		if err != nil {
			panic("invalid port in uri. format is " + URIFORMAT)
		}
	}
	// get the base DN
	if fields[4] == "" {
		panic("missing base DN in URI. format is " + URIFORMAT)
	}
	cli.BaseDN = fields[4]
	return
}

// Search runs a search query against the entire subtree of the LDAP base DN
func (cli *Client) Search(base, filter string, attributes []string) (entries []ldap.Entry, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.Search(base=%q, filter=%q, attributes=%q) -> %v",
				base, filter, attributes, e)
		}
	}()
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
	sr, err := cli.conn.Search(searchRequest)
	if err != nil {
		panic(err)
	}
	for _, entry := range sr.Entries {
		entries = append(entries, *entry)
	}
	return
}

// GetUserID returns the uid of a given user
//
// example: cli.GetUserId("mail=jvehent@mozilla.com")
func (cli *Client) GetUserId(shortdn string) (uid string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserId(shortdn=%q) -> %v",
				shortdn, e)
		}
	}()
	entries, err := cli.Search("", "("+shortdn+")", []string{"uid"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "uid" {
				continue
			}
			for _, val := range attr.Values {
				uid = val
			}
		}
	}
	if uid == "" {
		err = fmt.Errorf("no uid found in the attributes of user '%s'", shortdn)
	}
	return
}

// GetUserFullNameByEmail returns the distinguished name of a given user using his ID
//
// example: cli.GetUserFullNameByEmail("jvehent@mozilla.com")
func (cli *Client) GetUserFullNameByEmail(email string) (fullName string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserFullNameByEmail(mail=%q) -> %v", email, e)
		}
	}()
	entries, err := cli.Search("", "(mail="+email+")", []string{"cn"})
	if err != nil {
		panic(err)
	}
	if len(entries) != 1 {
		panic(fmt.Sprintf("found %d entries matching mail %q, expected 1", len(entries), email))
	}
	fullName = entries[0].GetAttributeValue("cn")
	return
}

// GetUserDNByID returns the distinguished name of a given user using his ID
//
// example: cli.GetUserDNByID("jvehent")
func (cli *Client) GetUserDNById(uid string) (dn string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserDNByID(uid=%q) -> %v", uid, e)
		}
	}()
	entries, err := cli.Search("", "(uid="+uid+")", []string{"mail"})
	if err != nil {
		panic(err)
	}
	if len(entries) != 1 {
		panic(fmt.Sprintf("found %d entries matching uid %q, expected 1", len(entries), uid))
	}
	dn = entries[0].DN
	return
}

// GetUserUidNumber returns the UID number of a user using a shortdn
//
// example: cli.GetUserUidNumber("mail=jvehent@mozilla.com")
func (cli *Client) GetUserUidNumber(shortdn string) (uidNumber uint64, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserUidNumber(shortdn=%q) -> %v",
				shortdn, e)
		}
	}()
	entries, err := cli.Search("", "("+shortdn+")", []string{"uidNumber"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "uidNumber" {
				continue
			}
			for _, val := range attr.Values {
				uidNumber, err = strconv.ParseUint(val, 10, 64)
				if err != nil {
					panic(err)
				}
			}
		}
	}
	if uidNumber < 0 {
		err = fmt.Errorf("no uidNumber found in the attributes of user '%s'", shortdn)
	}
	return
}

// GetUserSSHPublicKeys returns a list of public keys defined in a user's sshPublicKey
// LDAP attribute. If no public key is found, the list is empty.
//
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
//
// example: cli.GetUserSSHPublicKeys("mail=jvehent@mozilla.com")
func (cli *Client) GetUserSSHPublicKeys(shortdn string) (pubkeys []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserSSHPublicKeys(shortdn=%q) -> %v",
				shortdn, e)
		}
	}()
	entries, err := cli.Search("", "("+shortdn+")", []string{"sshPublicKey"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "sshPublicKey" {
				continue
			}
			for _, val := range attr.Values {
				if len(val) < 10 || val[0:3] != "ssh" {
					continue
				}
				pubkeys = append(pubkeys, strings.Trim(val, "\n"))
			}
		}
	}
	return
}

// GetUserPGPFingerprint returns a PGP fingerprint for the user, or an error if no fingerprint is found.
//
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
//
// example: cli.GetUserPGPFingerprint("mail=jvehent@mozilla.com")
func (cli *Client) GetUserPGPFingerprint(shortdn string) (fp string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserPGPFingerprint(shortdn=%q) -> %v",
				shortdn, e)
		}
	}()
	entries, err := cli.Search("", "("+shortdn+")", []string{"pgpFingerprint"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "pgpFingerprint" {
				continue
			}
			for _, fp = range attr.Values {
				// remove spaces
				fp = strings.Replace(fp, " ", "", -1)
				if len(fp) == 40 {
					return
				}
			}
		}
	}
	panic("no fingerprint found in ldap")
}

// GetUserPGPKey returns a PGP public key for the user, or an error if no key is found.
// The fingerprint of the key is first search in LDAP, then used to find the public key
// on gpg.mozilla.org.
//
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
//
// example: cli.GetUserPGPKey("mail=jvehent@mozilla.com")
func (cli *Client) GetUserPGPKey(shortdn string) (key []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserPGPKey(shortdn=%q) -> %v",
				shortdn, e)
		}
	}()
	fp, err := cli.GetUserPGPFingerprint(shortdn)
	if err != nil {
		panic(err)
	}
	re := regexp.MustCompile(`^0x[ABCDEF0-9]{8,64}$`)
	if !re.MatchString("0x" + fp) {
		panic("Invalid key id. Must be in format '0x[ABCDEF0-9]{8,64}")
	}
	resp, err := http.Get("http://gpg.mozilla.org/pks/lookup?op=get&options=mr&search=0x" + fp)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		panic("keyserver lookup error: " + http.StatusText(resp.StatusCode))
	}
	key, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return
}

// GetUsersInGroups takes a list of ldap groups and returns a list of unique members
// that belong to at least one of the group. Duplicates are removed, so you only get
// members once even if they belong to several groups.
//
// example: cli.GetUsersInGroups([]string{"sysadmins", "svcops", "mojitomakers"})
func (cli *Client) GetUsersInGroups(groups []string) (userdns []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUsersInGroups(groups=%q) -> %v",
				strings.Join(groups, ","), e)
		}
	}()
	q := "(|"
	for _, group := range groups {
		q += "(cn=" + group + ")"
	}
	q += ")"
	entries, err := cli.Search("ou=groups,"+cli.BaseDN, q, []string{"member"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "member" {
				continue
			}
			for _, val := range attr.Values {
				for _, knowndn := range userdns {
					if val == knowndn {
						goto skipit
					}
				}
				userdns = append(userdns, val)
			skipit:
			}
		}
	}
	return
}

// GetEnabledUsersInGroups takes a list of ldap groups and returns a list of unique members
// that belong to at least one of the group. Duplicates and disabled users are removed, so
// you only get members once even if they belong to several groups.
//
// example: cli.GetEnabledUsersInGroups([]string{"sysadmins", "svcops", "mojitomakers"})
func (cli *Client) GetEnabledUsersInGroups(groups []string) (userdns []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetEnabledUsersInGroups(groups=%q) -> %v",
				strings.Join(groups, ","), e)
		}
	}()
	usersingroups, err := cli.GetUsersInGroups(groups)
	if err != nil {
		panic(err)
	}
	q := "(&(!(employeeType=DISABLED))(|"
	for _, userdn := range usersingroups {
		q += "(" + strings.Split(userdn, ",")[0] + ")"
	}
	q += "))"
	entries, err := cli.Search(cli.BaseDN, q, []string{"DN"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, knowndn := range userdns {
			if entry.DN == knowndn {
				goto skipit
			}
		}
		userdns = append(userdns, entry.DN)
	skipit:
	}
	return
}

// GetUserEmailByUid returns the first email address found in the user's attributes
//
// example: cli.GetUserEmailByUid("jvehent")
func (cli *Client) GetUserEmailByUid(uid string) (mail string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserEmailByUid(uid=%q) -> %v",
				uid, e)
		}
	}()
	entries, err := cli.Search("", "(uid="+uid+")", []string{"mail"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "mail" {
				continue
			}
			if len(attr.Values) > 0 {
				return attr.Values[0], nil
			}
		}
	}
	panic("no mail attribute found")
}

// GetUserEmail returns the first email address found in the user's attributes
//
// example: cli.GetUserEmail("mail=jvehent@mozilla.com")
func (cli *Client) GetUserEmail(shortdn string) (mail string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetUserEmail(shortdn=%q) -> %v",
				shortdn, e)
		}
	}()
	entries, err := cli.Search("", "("+shortdn+")", []string{"mail"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "mail" {
				continue
			}
			if len(attr.Values) > 0 {
				return attr.Values[0], nil
			}
		}
	}
	panic("no mail attribute found")
}

// GetGroupsOfUser returns a list of groups a given user belongs to. This function returns the DN
// of all groups, including posix and scm groups.
//
// dn is the distinguished name of the user, such as "mail=jvehent@mozilla.com,o=com,dc=mozilla"
//
// example: cli.GetGroupsOfUser("mail=jvehent@mozilla.com,o=com,dc=mozilla")
func (cli *Client) GetGroupsOfUser(dn string) (groups []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("mozldap.GetGroupsOfUser(dn=%q) -> %v", dn, e)
		}
	}()
	uid, err := cli.GetUserId(strings.Split(dn, ",")[0])
	if err != nil {
		panic(err)
	}
	mail, err := cli.GetUserEmail(strings.Split(dn, ",")[0])
	if err != nil {
		panic(err)
	}
	entries, err := cli.Search("ou=groups,"+cli.BaseDN, "(|(member="+dn+")(memberUID="+uid+")(memberUID="+mail+"))", []string{"DN"})
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		groups = append(groups, entry.DN)
	}
	return
}
