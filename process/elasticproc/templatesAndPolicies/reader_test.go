package templatesAndPolicies

import (
	"testing"

	indexer "github.com/multiversx/mx-chain-es-indexer-go/process/dataindexer"
	"github.com/stretchr/testify/require"
)

func TestTemplatesAndPolicyReaderNoKibana_GetElasticTemplatesAndPolicies(t *testing.T) {
	t.Parallel()

	reader := NewTemplatesAndPolicyReader()

	templates, policies, err := reader.GetElasticTemplatesAndPolicies()
	require.Nil(t, err)
	require.Len(t, policies, 0)
	require.Len(t, templates, 29)
	require.Contains(t, templates, indexer.DrwaDenialsIndex)
	require.Contains(t, templates, indexer.DrwaIdentitiesIndex)
	require.Contains(t, templates, indexer.DrwaHolderComplianceIndex)
	require.Contains(t, templates, indexer.DrwaAttestationsIndex)
	require.Contains(t, templates, indexer.DrwaTokenPoliciesIndex)
	require.Contains(t, templates, indexer.DrwaControlEventsIndex)
}
