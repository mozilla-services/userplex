// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent <ulfr@mozilla.com>

package main

import (
	"bytes"
	"fmt"
	"log"
	"net/smtp"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/mozilla-services/userplex/modules"
)

func processNotifications(conf conf, notifchan chan modules.Notification, notifdone chan bool) {
	defer func() {
		notifdone <- true
	}()
	smtpaggrnotif := make(map[string][]modules.Notification)
	for n := range notifchan {
		log.Println("[info] got notification for", n.Recipient, "from module", n.Module)
		switch n.Mode {
		case "smtp":
			if _, ok := smtpaggrnotif[n.Recipient]; !ok {
				var ntfs []modules.Notification
				ntfs = append(ntfs, n)
				smtpaggrnotif[n.Recipient] = ntfs
			} else {
				smtpaggrnotif[n.Recipient] = append(smtpaggrnotif[n.Recipient], n)
			}
		default:
			log.Println("[error] userplex does not support notification type ", n.Mode)
		}
	}
	log.Println("[info] all notifications have been received, proceeding with sending.")
	sendEmailNotifications(conf, smtpaggrnotif)
}

func sendEmailNotifications(conf conf, smtpaggrnotif map[string][]modules.Notification) {
	for rcpt, ntfs := range smtpaggrnotif {
		var (
			body        []byte
			mustEncrypt = false
			err         error
		)
		log.Println("[info] sending", len(ntfs), "notifications to recipient", rcpt)
		for _, notif := range ntfs {
			body = append(body, []byte(fmt.Sprintf("----- %s -----\n%s\n", notif.Module, notif.Body))...)
			if notif.MustEncrypt {
				// if at least one notification in the entire pool wishes to be encrypted, encrypt all
				mustEncrypt = true
			}
		}
		if mustEncrypt {
			body, err = encryptMailBody(conf, body, rcpt)
			if err != nil {
				log.Printf("[error] failed to encrypt notification body for recipient %s: %v. Notification was not sent.", rcpt, err)
				continue
			}
		}
		if *dryrun && !*drynotif {
			log.Printf("[dryrun] would have sent email notification to %q with body\n%s\n", rcpt, body)
		} else {
			err = sendMail(conf, body, rcpt)
			if err != nil {
				log.Println("[error] failed to send email notification to", rcpt, ": %v", err)
			}
		}
	}
}

// encryptMailBody retrieves the PGP fingerprint of a recipient from ldap, then
// queries the gpg server to retrieve the public key and encrypts the body with it.
func encryptMailBody(conf conf, origBody []byte, rcpt string) (body []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("encryptMailBody-> %v", e)
		}
	}()
	key, err := conf.Ldap.cli.GetUserPGPKey("mail=" + rcpt)
	if err != nil {
		panic(err)
	}
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(key))
	if err != nil {
		panic(err)
	}
	encbuf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(encbuf, el, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	_, err = w.Write([]byte(origBody))
	if err != nil {
		panic(err)
	}
	err = w.Close()
	if err != nil {
		panic(err)
	}
	armbuf := bytes.NewBuffer(nil)
	w, err = armor.Encode(armbuf, "PGP MESSAGE", nil)
	if err != nil {
		panic(err)
	}
	_, err = w.Write(encbuf.Bytes())
	if err != nil {
		panic(err)
	}
	w.Close()
	body = armbuf.Bytes()
	return
}

func sendMail(conf conf, body []byte, rcpt string) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("sendMail-> %v", e)
		}
	}()
	var auth smtp.Auth
	if conf.Notifications.Email.Auth.User != "" && conf.Notifications.Email.Auth.Pass != "" {
		auth = smtp.PlainAuth("", conf.Notifications.Email.Auth.User, conf.Notifications.Email.Auth.Pass, conf.Notifications.Email.Host)
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
		fmt.Sprintf("%s:%d", conf.Notifications.Email.Host, conf.Notifications.Email.Port),
		auth,
		conf.Notifications.Email.From,
		[]string{rcpt},
		[]byte(fmt.Sprintf(`From: %s
To: %s
Cc: %s
Reply-to: %s
Subject: Userplex account changes
Date: %s

%s
%s
`, conf.Notifications.Email.From, rcpt, conf.Notifications.Email.Cc, conf.Notifications.Email.ReplyTo,
			time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700"), prefix, body)),
	)
	if err != nil {
		panic(err)
	}
	return
}
