package authorizer

import (
	"context"
	"fmt"
	"strings"

	admreg "k8s.io/api/admissionregistration/v1"
	"k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/webhook-operator/api"
	"github.com/cert-manager/webhook-operator/indexers"
)

// NamedUserAuthorizer authorizes users authenticating with a ServiceAccount
// token for identifiers that are specified as 'service names' on Validating &
// Mutating webhook resources as well as CRDs that name the passed user.
// It will check for the following annotations, and match accordingly:
// * webhooks.cert-manager.io/authorized-usernames
// * webhooks.cert-manager.io/authorized-groups
// Both of these can be specified as a comma separated list of usernames or
// group names, and will be matched against the UserInfo accordingly.
type NamedUserAuthorizer struct {
	client.Client
}

var _ api.UserAuthorizer = &NamedUserAuthorizer{}

func (a *NamedUserAuthorizer) IsAuthorized(userInfo v1.UserInfo, identifier string) (bool, error) {
	ns, name, err := extractServiceNamespaceName(identifier)
	if err != nil {
		return false, nil
	}

	ctx := context.Background()
	var validatingHooks admreg.ValidatingWebhookConfigurationList
	if err := a.List(ctx, &validatingHooks, client.MatchingFields{indexers.ValidatingWebhookServiceNameKey: ns+"/"+name}); err != nil {
		return false, err
	}

	return len(validatingHooks.Items) > 0, nil
}

func extractServiceNamespaceName(hostname string) (namespace, name string, err error) {
	s := strings.Split(hostname, ".")
	if len(s) != 3 {
		return "", "", fmt.Errorf("invalid URL format")
	}
	if s[0] == "" || s[1] == "" {
		return "", "", fmt.Errorf("invalid URL %q", hostname)
	}
	return s[1], s[0], nil
}
