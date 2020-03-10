package api

import (
	authv1 "k8s.io/api/authentication/v1"
)

const (
	// WebhookServingSignerName is the name of the signer to be used on CSRs
	// that should be signed by the webhook-operator.
	WebhookServingSignerName = "cert-manager.io/webhook-serving"
)

// A UserAuthorizer can make decisions about whether a Kubernetes user,
// identified by UserInfo, is authorized to request an identity document for
// the given identifier(s) (i.e. a hostname).
// A concrete example of this interface is a ValidatingWebhookConfiguration
// resource which names a Kubernetes user or group that has permission to
// request a certificate for the given DNS name/identifier.
type UserAuthorizer interface {
	IsAuthorized(userInfo authv1.UserInfo, identifier string) (bool, error)
}

// An Injectable is an interface for accessing resources that allow a caBundle
// to be injected into them.
// This is used to access and modify resources in the Kubernetes API in order
// to manage the caBundle field.
// Calling the SetCA method must NOT update the resource in the API server.
type Injectable interface {
	SetCA(pem []byte)
}
