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
	"strings"
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
	sendSmtpNotifications(conf, smtpaggrnotif)
}

func sendSmtpNotifications(conf conf, smtpaggrnotif map[string][]modules.Notification) {
	for rcpt, ntfs := range smtpaggrnotif {
		var (
			body        []byte
			mustEncrypt bool = false
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
		if *dryrun {
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
func encryptMailBody(conf conf, orig_body []byte, rcpt string) (body []byte, err error) {
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
	_, err = w.Write([]byte(orig_body))
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
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(conf.Notifications.Smtp.Relay)
	if err != nil {
		panic(err)
	}

	// Set the sender and recipient first
	err = c.Mail(conf.Notifications.Smtp.From)
	if err != nil {
		panic(err)
	}
	err = c.Rcpt(rcpt)
	if err != nil {
		panic(err)
	}
	if conf.Notifications.Smtp.Cc != "" {
		for _, cc := range strings.Split(conf.Notifications.Smtp.Cc, ",") {
			err = c.Rcpt(cc)
			if err != nil {
				panic(err)
			}
		}
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		panic(err)
	}
	cdate := time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700")
	// If the body is encrypted PGP, put it inside a MIME enveloppe
	if len(body) > 30 && fmt.Sprintf("%s", body[0:27]) == "-----BEGIN PGP MESSAGE-----" {
		_, err = fmt.Fprintf(wc, `From: %s
To: %s
Cc: %s
Subject: Userplex account changes
Content-Type: multipart/encrypted; boundary="1450886287.E58FD0.11006"; protocol="application/pgp-encrypted"
MIME-Version: 1.0
Auto-Submitted: auto-generated
Date: %s

--1450886287.E58FD0.11006
Date: %s
MIME-Version: 1.0
Content-Type: application/pgp-encrypted; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Version: 1


--1450886287.E58FD0.11006
Date: %s
MIME-Version: 1.0
Content-Type: application/octet-stream; charset="UTF-8"
Content-Transfer-Encoding: 7bit
Content-Disposition: inline; filename="encrypted.asc"

%s


--1450886287.E58FD0.11006--`,
			conf.Notifications.Smtp.From,
			rcpt,
			conf.Notifications.Smtp.Cc,
			cdate,
			cdate,
			cdate,
			body)
	} else {
		// If the body is not encrypted, we just store it as is. No Mime.
		_, err = fmt.Fprintf(wc, `From: %s
To: %s
Cc: %s
Subject: Userplex account changes
Auto-Submitted: auto-generated
Date: %s

%s`,
			conf.Notifications.Smtp.From,
			rcpt,
			conf.Notifications.Smtp.Cc,
			cdate,
			body)
	}

	if err != nil {
		panic(err)
	}
	err = wc.Close()
	if err != nil {
		panic(err)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		panic(err)
	}
	return
}
