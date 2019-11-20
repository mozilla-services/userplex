module go.mozilla.org/userplex/modules

go 1.13

require (
	github.com/aws/aws-sdk-go v1.25.30
	go.mozilla.org/person-api v0.0.0-20191120210847-5e8f6374ee7e
	go.mozilla.org/userplex/notifications v0.0.0
)

replace go.mozilla.org/userplex/notifications => ../notifications
