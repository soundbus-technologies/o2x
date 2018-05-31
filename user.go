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
	PwSaltByteLen = 16
	PwHashByteLen = 32
)

type UserStore interface {
	Save(u *User) (err error)
	Find(id string) (u *User, err error)
}

func NewUserStore() UserStore {
	return &MemoryUserStore{
		data: make(map[string]*User),
	}
}

type MemoryUserStore struct {
	sync.RWMutex
	data map[string]*User
}

func (cs *MemoryUserStore) Find(id string) (u *User, err error) {
	cs.RLock()
	defer cs.RUnlock()
	if c, ok := cs.data[id]; ok {
		u = c
		return
	}
	err = errors.New("not found")
	return
}

func (cs *MemoryUserStore) Save(u *User) (err error) {
	cs.Lock()
	defer cs.Unlock()
	cs.data[u.UserID] = u
	return
}

type User struct {
	UserID   string `bson:"_id" json:"user_id"`
	Nickname string `bson:"nickname,omitempty" json:"nickname,omitempty"`
	Password []byte `bson:"password" json:"password"`
	Salt     []byte `bson:"salt" json:"salt"`
}

func (u *User) GetUserID() string {
	return u.UserID
}

func (u *User) SetUserID(userID string) {
	u.UserID = userID
}

func (u *User) GetNickname() string {
	return u.Nickname
}

func (u *User) SetNickname(nickname string) {
	u.Nickname = nickname
}

func (u *User) calcHash(password string) (hash []byte, err error) {
	return scrypt.Key([]byte(password), u.Salt, 1<<14, 8, 1, PwHashByteLen)
}

func (u *User) SetPassword(password string) {
	salt := make([]byte, PwSaltByteLen)
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

func (u *User) Match(password string) bool {
	hash, err := u.calcHash(password)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return reflect.DeepEqual(hash, u.Password)
}
