module go.mozilla.org/userplex

go 1.13

require (
	github.com/PagerDuty/go-pagerduty v0.0.0-20191024223038-94ee1c55dbdb // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/gorhill/cronexpr v0.0.0-20180427100037-88b0669f7d75 // indirect
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0-20191022224028-a40c7561d74c // indirect
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/urfave/cli v1.22.1
	github.com/zorkian/go-datadog-api v2.24.0+incompatible // indirect
	go.mozilla.org/mozldap v0.0.0-20160924171832-b72e7f45c7f9
	go.mozilla.org/person-api v0.0.0-20191120210847-5e8f6374ee7e
	go.mozilla.org/sops v0.0.0-20190912205235-14a22d7a7060
	go.mozilla.org/userplex/modules v0.0.0
	go.mozilla.org/userplex/modules/authorizedkeys v0.0.0
	go.mozilla.org/userplex/modules/aws v0.0.0-20190722201609-d7c0cb093237
	go.mozilla.org/userplex/notifications v0.0.0
	golang.org/x/crypto v0.0.0-20191108234033-bd318be0434a
	gopkg.in/ldap.v2 v2.5.1 // indirect
	gopkg.in/yaml.v2 v2.2.5
)

replace go.mozilla.org/userplex/modules/authorizedkeys => ./modules/authorizedkeys

replace go.mozilla.org/userplex/modules/aws => ./modules/aws

replace go.mozilla.org/userplex/modules => ./modules

replace go.mozilla.org/userplex/notifications => ./notifications
