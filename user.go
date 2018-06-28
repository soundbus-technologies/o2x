// authors: wangoo
// created: 2018-05-31
// oauth2 user extension

package o2x

import (
	"golang.org/x/crypto/scrypt"
	"io"
	"crypto/rand"
	"reflect"
	"log"
	"sync"
	"errors"
)

const (
	pwSaltByteLen = 16
	pwHashByteLen = 32
)

var (
	UserType          = reflect.TypeOf(new(User)).Elem()
	SimpleUserPtrType = reflect.TypeOf(&SimpleUser{})
)

type UserStore interface {
	Save(u User) (err error)
	Find(id string) (u User, err error)
}

type User interface {
	GetUserID() string
	Match(password string) bool
}

func IsUserType(t reflect.Type) bool {
	return t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct && t.Implements(UserType)
}

func NewUser(t reflect.Type) User {
	return reflect.New(t.Elem()).Interface().(User)
}

// -------------------------------
func NewUserStore() UserStore {
	return &MemoryUserStore{
		data: make(map[string]User),
	}
}

type MemoryUserStore struct {
	sync.RWMutex
	data map[string]User
}

func (cs *MemoryUserStore) Find(id string) (u User, err error) {
	cs.RLock()
	defer cs.RUnlock()
	if c, ok := cs.data[id]; ok {
		u = c
		return
	}
	err = errors.New("not found")
	return
}

func (cs *MemoryUserStore) Save(u User) (err error) {
	cs.Lock()
	defer cs.Unlock()
	cs.data[u.GetUserID()] = u
	return
}

// -------------------------------
type SimpleUser struct {
	UserID   string `bson:"_id" json:"user_id"`
	Nickname string `bson:"nickname,omitempty" json:"nickname,omitempty"`
	Password []byte `bson:"password" json:"password"`
	Salt     []byte `bson:"salt" json:"salt"`
}

func (u *SimpleUser) GetUserID() string {
	return u.UserID
}

func (u *SimpleUser) SetUserID(userID string) {
	u.UserID = userID
}

func (u *SimpleUser) GetNickname() string {
	return u.Nickname
}

func (u *SimpleUser) SetNickname(nickname string) {
	u.Nickname = nickname
}

func (u *SimpleUser) calcHash(password string) (hash []byte, err error) {
	return scrypt.Key([]byte(password), u.Salt, 1<<14, 8, 1, pwHashByteLen)
}

func (u *SimpleUser) SetPassword(password string) {
	salt := make([]byte, pwSaltByteLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		log.Fatal(err)
	}
	u.Salt = salt

	hash, err := u.calcHash(password)
	if err != nil {
		log.Fatal(err)
	}
	u.Password = hash
}

func (u *SimpleUser) Match(password string) bool {
	hash, err := u.calcHash(password)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return reflect.DeepEqual(hash, u.Password)
}
