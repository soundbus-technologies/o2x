// authors: wangoo
// created: 2018-05-31
// oauth2 client extension

package o2x

import "gopkg.in/oauth2.v3"

type Oauth2ClientInfo interface {
	oauth2.ClientInfo
	GetScope() string
}

type Oauth2ClientStore interface {
	oauth2.ClientStore
	Set(id string, cli oauth2.ClientInfo) (err error)
}
