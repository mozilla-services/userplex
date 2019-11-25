module go.mozilla.org/userplex/modules/authorizedkeys

go 1.13

require (
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/person-api v0.0.0-20191125182003-e07ecb512bfe
	go.mozilla.org/userplex/modules v0.0.0
	go.mozilla.org/userplex/notifications v0.0.0
)

replace go.mozilla.org/userplex/modules => ../

replace go.mozilla.org/userplex/notifications => ../../notifications
