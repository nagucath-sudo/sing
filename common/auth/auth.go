package auth

import "github.com/sagernet/sing/common"

type User struct {
	Username string
	Password string
}

// Verifier is the minimal reverse-control contract required by protocol
// servers. Authenticator remains the standard static implementation; an
// embedding application may supply a verifier backed by its own immutable
// runtime snapshot without moving persistence into the protocol package.
type Verifier interface {
	Verify(username string, password string) bool
}

type Authenticator struct {
	userMap map[string][]string
}

var _ Verifier = (*Authenticator)(nil)

func NewAuthenticator(users []User) *Authenticator {
	if len(users) == 0 {
		return nil
	}
	au := &Authenticator{
		userMap: make(map[string][]string),
	}
	for _, user := range users {
		au.userMap[user.Username] = append(au.userMap[user.Username], user.Password)
	}
	return au
}

func (au *Authenticator) Verify(username string, password string) bool {
	passwordList, ok := au.userMap[username]
	return ok && common.Contains(passwordList, password)
}
