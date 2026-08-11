package context_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/internal/context"
)

// A stale SM context must not remove the canonical reference of the SM context that
// replaced it, otherwise the newer one becomes unreachable and leaks its UE IP address.
func TestRemoveSMContextKeepsCanonicalRefOfNewerSMContext(t *testing.T) {
	initConfig()

	const (
		supi         = "imsi-001016100000041"
		pduSessionID = int32(1)
	)

	newSMContextForSupi := func() *context.SMContext {
		smContext := context.NewSMContext(supi, pduSessionID)
		require.NotNil(t, smContext)
		// HandlePDUSessionSMContextCreate attaches the create data right after
		// NewSMContext; RemoveSMContext reads Supi out of it.
		smContext.SmfPduSessionSmContextCreateData = &models.SmfPduSessionSmContextCreateData{
			Supi:         supi,
			PduSessionId: pduSessionID,
		}
		return smContext
	}

	oldSMContext := newSMContextForSupi()
	newSMContext := newSMContextForSupi()
	require.NotEqual(t, oldSMContext.Ref, newSMContext.Ref)

	// NewSMContext has already handed the canonical name over to newSMContext.
	require.Equal(t, newSMContext, context.GetSMContextById(supi, pduSessionID))

	context.RemoveSMContext(oldSMContext.Ref)

	require.Nil(t, context.GetSMContextByRef(oldSMContext.Ref))
	require.Equal(t, newSMContext, context.GetSMContextById(supi, pduSessionID),
		"removing the stale SM context must not detach the newer one from its canonical name")

	// The owner of the canonical name still cleans it up.
	context.RemoveSMContext(newSMContext.Ref)
	require.Nil(t, context.GetSMContextById(supi, pduSessionID))
}
