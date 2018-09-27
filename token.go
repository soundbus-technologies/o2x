// authors: wangoo
// created: 2018-06-01
// oauth2 token extension

package o2x

import "gopkg.in/oauth2.v3"

type O2TokenStore interface {
	oauth2.TokenStore

	/**
	删除该用户在指定client下的所有token
	 */
	RemoveByAccount(userID string, clientID string) (err error)

	/**
	删除该用户的所有token
	 */
	RemoveByAccountNoClient(userID string) (err error)

	/**
	获取该用户在指定client下的token
	 */
	GetByAccount(userID string, clientID string) (ti oauth2.TokenInfo, err error)
}
