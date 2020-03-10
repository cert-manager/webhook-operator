package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	auth "k8s.io/api/authentication/v1"
	capi "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	capiclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/webhook-operator/api"
)

// ApprovalReconciler will attempt to automatically approve CSRs that are
// identified as being referenced by a
type ApprovalReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme

	// SignerName is the name of the 'signer' used to denote CSRs that should
	// be auto-approved by the approval controller.
	SignerName string

	// The UserAuthorizer will decide whether a given UserInfo is authorized to
	// request certificates for the given hostname.
	Authorizer api.UserAuthorizer

	// ExpansionClient is used to update the `/approval` subresource of CSR
	// resources. The controller-runtime `client.Client` does not expose this
	// functionality, so we utilise the typed client in client-go instead.
	ExpansionClient capiclient.CertificateSigningRequestExpansion
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
func (r *ApprovalReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certificatesigningrequests", req.NamespacedName)

	csr := capi.CertificateSigningRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Fast-path for approved requested
	if allowed, denied := api.GetCertApprovalCondition(&csr.Status); allowed || denied {
		return ctrl.Result{}, nil
	}

	// Ignore all requests if they don't specify signerName
	if csr.Spec.SignerName == nil {
		log.Info("spec.signerName field not set on CSR resource, this indicates the Kubernetes apiserver version is not 1.18+")
		return ctrl.Result{}, nil
	}

	// Ensure the signerName is one we should act upon
	if *csr.Spec.SignerName != api.WebhookServingSignerName {
		log.V(2).Info("Unrecognised spec.signerName, ignoring", "signerName", *csr.Spec.SignerName)
		return ctrl.Result{}, nil
	}

	x509Cr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		log.Error(err, "Failed to parse spec.request on CSR resource")
		return ctrl.Result{}, nil
	}

	// Check if the request and is valid, given the requested options and the
	// authorizer configured.
	if !isWebhookServingCSR(log, csr.Spec, x509Cr) {
		return ctrl.Result{}, nil
	}

	allowed, err := userAuthorizedForRequest(r.Authorizer, csr.Spec, x509Cr)
	if err != nil {
		log.Error(err, "Failed to check authorization status for requesting user")
		return ctrl.Result{}, err
	}
	if !allowed {
		log.Info("User not authorized to request certificates for names")
		return ctrl.Result{}, nil
	}

	log.Info("Auto-approving CSR")
	approvedCSR := csr.DeepCopy()
	approvedCSR.Status.Conditions = append(approvedCSR.Status.Conditions, capi.CertificateSigningRequestCondition{
		Type:           capi.CertificateApproved,
		Reason:         "AutoApproved",
		Message:        "Automatically approved by webhook-operator",
		LastUpdateTime: v1.NewTime(time.Now()),
	})
	if _, err := r.ExpansionClient.UpdateApproval(approvedCSR); err != nil {
		log.Error(err, "Failed to update Approved condition")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func userAuthorizedForRequest(authorizer api.UserAuthorizer, req capi.CertificateSigningRequestSpec, csr *x509.CertificateRequest) (bool, error) {
	// Check the specified CN and DNSNames and ensure the requesting user has
	// permission to request for these identifiers.
	identSet := sets.NewString(csr.DNSNames...)
	if csr.Subject.CommonName != "" {
		identSet.Insert(csr.Subject.CommonName)
	}
	identifiers := identSet.List()

	extraValues := make(map[string]auth.ExtraValue)
	for k, v := range req.Extra {
		extraValues[k] = auth.ExtraValue(v)
	}
	userInfo := auth.UserInfo{
		Username: req.Username,
		UID:      req.UID,
		Groups:   req.Groups,
		Extra:    extraValues,
	}

	for _, identifier := range identifiers {
		allowed, err := authorizer.IsAuthorized(userInfo, identifier)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}

	return true, nil
}

// isWebhookServingCSR will check if the provided CSR is:
// * ensures no other parameters are specified
// * specifies only a CN/dnsName valid for the service specified on that webhook
// * requested by a ServiceAccount named on a ValidatingWebhook, MutatingWebhook or CRD resource
func isWebhookServingCSR(log logr.Logger, req capi.CertificateSigningRequestSpec, csr *x509.CertificateRequest) bool {
	// Don't allow IPAddresses, EmailAddresses or URIs
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		log.Info("Request specifies IPAddresses, EmailAddresses or URIs", "ips", csr.IPAddresses, "emails", csr.EmailAddresses, "uris", csr.URIs)
		return false
	}

	// Only allow KeyEncipherment, DigitalSignature and ServerAuth usages
	if !equalUnsorted(req.Usages, []capi.KeyUsage{
		capi.UsageDigitalSignature,
		capi.UsageKeyEncipherment,
		capi.UsageServerAuth,
	}) {
		log.Info("Request specifies invalid key usages", "usages", req.Usages)
		return false
	}

	return true
}

func (r *ApprovalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.CertificateSigningRequest{}).
		Complete(r)
}

func parseCSR(csr []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(csr)
	if b.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected PEM data of type 'CERTIFICATE REQUEST' but found %q", b.Type)
	}

	return x509.ParseCertificateRequest(b.Bytes)
}

func equalUnsorted(l, r []capi.KeyUsage) bool {
	lS := sets.NewString()
	for _, v := range l {
		lS.Insert(string(v))
	}
	rS := sets.NewString()
	for _, v := range r {
		rS.Insert(string(v))
	}
	return lS.Equal(rS)
}
