package indexers

import (
	admreg "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// ValidatingWebhookServiceNameKey is a synthetic field selector that
	// allows querying for ValidatingWebhookConfiguration resources that
	// declare a webhook entry that points to the given service name.
	// If any webhook entries point to a service name being queried, the
	// resource will be returned.
	ValidatingWebhookServiceNameKey = ".synthetic.serviceName"
)

// RegisterValidatingWebhookConfigurationIndexers registers all indexers for
// ValidatingWebhookConfiguration resources.
func RegisterValidatingWebhookConfigurationIndexers(indexer client.FieldIndexer) {
	indexer.IndexField(&admreg.ValidatingWebhookConfiguration{}, ValidatingWebhookServiceNameKey, validatingWebhookServiceNameIndexerFunc)
}

func validatingWebhookServiceNameIndexerFunc(obj runtime.Object) []string {
	serviceNames := []string{}
	vwh := obj.(*admreg.ValidatingWebhookConfiguration)
	for _, wh := range vwh.Webhooks {
		if wh.ClientConfig.Service == nil {
			continue
		}
		serviceNames = append(serviceNames, wh.ClientConfig.Service.Namespace + "/" + wh.ClientConfig.Service.Name)
	}
	return serviceNames
}
