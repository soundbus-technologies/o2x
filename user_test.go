// authors: wangoo
// created: 2018-05-30
// test user

package o2x

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"fmt"
	"encoding/json"
)

func TestUser(t *testing.T) {
	u := &SimpleUser{}
	u.SetUserID("123")
	u.SetNickname("wongoo")

	assert.Equal(t, "123", u.GetUserID())
	assert.Equal(t, "wongoo", u.GetNickname())

	password := "my_password"
	u.SetRawPassword(password)

	assert.True(t, u.Match(password), "password should be match")

	js, err := json.Marshal(u)
	assert.Nil(t, err, err)
	fmt.Println(string(js))
}

func TestNewUser(t *testing.T) {
	u := NewUser(SimpleUserPtrType)
	fmt.Println("user:", u)

	u2 := u.(*SimpleUser)
	u2.SetUserID("u2")
	u2.SetNickname("u2")
	u2.SetRawPassword("pass")

	js, err := json.Marshal(u)
	assert.Nil(t, err, err)
	fmt.Println(string(js))
}

func TestIsUserType(t *testing.T) {
	fmt.Println(SimpleUserPtrType)
	fmt.Println(UserType)
	assert.True(t, IsUserType(SimpleUserPtrType))
}
