package notifications

import (
	"bytes"
	"fmt"
	"net/http"
	"net/smtp"
	"time"

	"go.mozilla.org/person-api"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type Config struct {
	Email struct {
		Host, From, Cc,
		ReplyTo, Subject string
		Port int
		Auth struct {
			User, Pass string
		}
	}
}

func SendEmail(conf Config, body []byte, person *person_api.Person) error {
	var err error
	body, err = EncryptMailBody(conf, body, person)
	if err != nil {
		log.Errorf("failed to encrypt notification body for recipient %s: %v. Notification was not sent.", person.PrimaryEmail.Value, err)
		return err
	}

	var auth smtp.Auth
	if conf.Email.Auth.User != "" && conf.Email.Auth.Pass != "" {
		auth = smtp.PlainAuth("", conf.Email.Auth.User, conf.Email.Auth.Pass, conf.Email.Host)
	}

	// If the body is encrypted PGP, put it inside a MIME enveloppe
	prefix := ""
	if len(body) > 30 && fmt.Sprintf("%s", body[0:27]) == "-----BEGIN PGP MESSAGE-----" {
		prefix = `
This message contains PGP encrypted data. If your email agent does
not automatically decrypt it, you can do so manually by saving the
PGP block below to a file and decrypting it with "gpg -d file.asc".
`
	}
	err = smtp.SendMail(
		fmt.Sprintf("%s:%d", conf.Email.Host, conf.Email.Port),
		auth,
		conf.Email.From,
		[]string{person.PrimaryEmail.Value},
		[]byte(fmt.Sprintf(`From: %s
To: %s
Cc: %s
Reply-to: %s
Subject: %s
Date: %s

%s
%s
`,
			conf.Email.From,
			person.PrimaryEmail.Value,
			conf.Email.Cc,
			conf.Email.ReplyTo,
			conf.Email.Subject,
			time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700"),
			prefix,
			body)),
	)
	if err != nil {
		return err
	}
	return nil
}

// encryptMailBody retrieves the PGP fingerprint of a recipient from ldap, then
// queries the gpg server to retrieve the public key and encrypts the body with it.
func EncryptMailBody(conf Config, origBody []byte, person *person_api.Person) ([]byte, error) {
	if len(person.GetPGPPublicKeys()) == 0 {
		return nil, fmt.Errorf("Person %s does not have any pgp keys.", person.GetLDAPUsername())
	}

	keyid := person.GetPGPPublicKeys()[0]
	entity, err := getKeyFromKeyServer("gpg.mozilla.org", keyid)
	if err != nil {
		log.Errorf("Error receiving key from keyserver: %s", err)
		return nil, err
	}

	encbuf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(encbuf, []*openpgp.Entity{&entity}, nil, nil, nil)
	if err != nil {
		log.Errorf("Error encrypted mail body: %s", err)
		return nil, err
	}
	_, err = w.Write([]byte(origBody))
	if err != nil {
		log.Errorf("Error writing original body to encrypted writer: %s", err)
		return nil, err
	}
	err = w.Close()
	if err != nil {
		log.Errorf("Error closing encrypted writer: %s", err)
		return nil, err
	}
	armbuf := bytes.NewBuffer(nil)
	w, err = armor.Encode(armbuf, "PGP MESSAGE", nil)
	if err != nil {
		log.Errorf("Error creating armor encoding writer: %s", err)
		return nil, err
	}
	_, err = w.Write(encbuf.Bytes())
	if err != nil {
		log.Errorf("Error writing armor encoded body: %s", err)
		return nil, err
	}
	err = w.Close()
	if err != nil {
		log.Errorf("Error closing armor encoded body: %s", err)
		return nil, err
	}
	body := armbuf.Bytes()
	return body, nil
}

func getKeyFromKeyServer(keyserver, fingerprint string) (openpgp.Entity, error) {
	url := fmt.Sprintf("https://%s/pks/lookup?op=get&options=mr&search=%s", keyserver, fingerprint)
	resp, err := http.Get(url)
	if err != nil {
		return openpgp.Entity{}, fmt.Errorf("error getting key from keyserver: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return openpgp.Entity{}, fmt.Errorf("keyserver returned non-200 status code %s", resp.Status)
	}
	ents, err := openpgp.ReadArmoredKeyRing(resp.Body)
	if err != nil {
		return openpgp.Entity{}, fmt.Errorf("could not read entities: %s", err)
	}
	if len(ents) == 0 {
		return openpgp.Entity{}, fmt.Errorf("no entities found")
	}
	return *ents[0], nil
}
