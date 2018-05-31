// authors: wangoo
// created: 2018-05-31
// oauth2 extension

package o2x

type UriFormatter interface {
	FormatRedirectUri(uri string) string
}
