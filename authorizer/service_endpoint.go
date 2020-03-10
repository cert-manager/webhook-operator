package authorizer

import (
	v1 "k8s.io/api/authentication/v1"

	"github.com/cert-manager/webhook-operator/api"
)

// ServiceEndpointAuthorizer will authorizer a user's request for a certificate
// by:
// * Checking the requesting user is associated with a ServiceAccount
// * Ch
type ServiceEndpointAuthorizer struct {
}

var _ api.UserAuthorizer = &ServiceEndpointAuthorizer{}

func (a *ServiceEndpointAuthorizer) IsAuthorized(userInfo v1.UserInfo, identifier string) (bool, error) {
	return true, nil
}
