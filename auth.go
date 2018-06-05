// authors: wangoo
// created: 2018-06-05
// oauth2 auth extension

package o2x

import (
	"sync"
	"strings"
	"errors"
)

type Auth interface {
	GetClientID() string
	SetClientID(id string)

	GetUserID() string
	SetUserID(id string)

	GetScope() string
	SetScope(scope string)

	// whether the Scope of current auth contains the given Scope
	Contains(scope string) bool
}

type AuthStore interface {
	// save auth
	Save(auth Auth) error

	// find auth by ClientID and UserID
	Find(clientId string, userID string) (auth Auth, err error)

	// whether the auth already exists
	Exist(auth Auth) bool
}

func ScopeContains(scope string, test string) bool {
	if scope == "" {
		return false
	}
	if test == "" {
		return true
	}

	arr := strings.Split(test, ",")

	for _, item := range arr {
		if !strings.Contains(scope, item) {
			return false
		}
	}
	return true
}

// --------------------------------------------------
type AuthModel struct {
	ClientID string
	UserID   string
	Scope    string
}

func (a *AuthModel) GetClientID() string {
	return a.ClientID
}

func (a *AuthModel) SetClientID(id string) {
	a.ClientID = id
}

func (a *AuthModel) GetUserID() string {
	return a.UserID
}

func (a *AuthModel) SetUserID(id string) {
	a.UserID = id
}

func (a *AuthModel) GetScope() string {
	return a.Scope
}

func (a *AuthModel) SetScope(scope string) {
	a.Scope = scope
}

func (a *AuthModel) Contains(scope string) bool {
	return ScopeContains(a.Scope, scope)
}

// --------------------------------------------------

type MemoryAuthStore struct {
	sync.RWMutex
	data map[string]map[string]string
}

func NewAuthStore() *MemoryAuthStore {
	return &MemoryAuthStore{
		data: make(map[string]map[string]string),
	}
}

func (as *MemoryAuthStore) Save(auth Auth) error {
	as.Lock()
	defer as.Unlock()
	if _, ok := as.data[auth.GetClientID()]; !ok {
		as.data[auth.GetClientID()] = make(map[string]string)
	}
	as.data[auth.GetClientID()][auth.GetUserID()] = auth.GetScope()
	return nil
}

func (as *MemoryAuthStore) Find(clientId string, userID string) (auth Auth, err error) {
	as.RLock()
	defer as.RUnlock()

	if c, ok := as.data[clientId]; ok {
		if scope, ok := c[userID]; ok {
			auth = &AuthModel{
				ClientID: clientId,
				UserID:   userID,
				Scope:    scope,
			}
			return
		}
	}
	err = errors.New("not found")
	return
}

func (as *MemoryAuthStore) Exist(auth Auth) bool {
	if c, ok := as.data[auth.GetClientID()]; ok {
		if scope, ok := c[auth.GetUserID()]; ok {
			return ScopeContains(scope, auth.GetScope())
		}
	}
	return false
}