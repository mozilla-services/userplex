module go.mozilla.org/userplex/modules/aws

go 1.13

require (
	github.com/aws/aws-sdk-go v1.25.30
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/person-api v0.0.0-20191120210847-5e8f6374ee7e
	go.mozilla.org/userplex/modules v0.0.0
	go.mozilla.org/userplex/notifications v0.0.0
)

replace go.mozilla.org/userplex/modules => ../

replace go.mozilla.org/userplex/notifications => ../../notifications
