package indexers

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Register(indexer client.FieldIndexer) {
	RegisterValidatingWebhookConfigurationIndexers(indexer)
}
