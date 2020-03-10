package authorizer

import (
	v1 "k8s.io/api/authentication/v1"

	"github.com/cert-manager/webhook-operator/api"
)

type AlwaysTrueAuthorizer struct{}

var _ api.UserAuthorizer = &AlwaysTrueAuthorizer{}

func (a *AlwaysTrueAuthorizer) IsAuthorized(userInfo v1.UserInfo, identifier string) (bool, error) {
	return true, nil
}
