package context

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/idgenerator"
)

const testSessRuleID = "SessRuleId-1"

// newGSMTestContext builds a minimal deterministic SMContext for golden tests.
// It intentionally does NOT use NewSMContext: that would touch the global
// TeidGenerator (nil in unit tests) and the smContextPool.
func newGSMTestContext() *SMContext {
	sessRule := NewSessionRule(&models.SessionRule{
		AuthSessAmbr: &models.Ambr{Uplink: "200 Kbps", Downlink: "100 Kbps"},
		AuthDefQos:   &models.AuthorizedDefaultQos{Var5qi: 9, Arp: &models.Arp{PriorityLevel: 8}},
		SessRuleId:   testSessRuleID,
	})
	return &SMContext{
		SmfPduSessionSmContextCreateData: &models.SmfPduSessionSmContextCreateData{
			Dnn:    "internet",
			SNssai: &models.Snssai{Sst: 1, Sd: "112232"},
			AnType: models.AccessType__3_GPP_ACCESS,
		},
		PDUSessionID:                 10,
		Pti:                          1,
		SelectedPDUSessionType:       nasMessage.PDUSessionTypeIPv4,
		PDUAddress:                   net.ParseIP("10.60.0.1").To4(),
		ProtocolConfigurationOptions: &ProtocolConfigurationOptions{},
		SessionRules:                 map[string]*SessionRule{testSessRuleID: sessRule},
		SelectedSessionRuleID:        testSessRuleID,
		defRuleID:                    1,
		QoSRuleIDGenerator:           idgenerator.NewGenerator(2, 255), // 1 is taken by defRuleID
		PacketFilterIDGenerator:      idgenerator.NewGenerator(1, 255),
		PCCRuleIDToQoSRuleID:         map[string]uint8{},
		PacketFilterIDToNASPFID:      map[string]uint8{},
	}
}

func TestGoldenBuildGSMPDUSessionEstablishmentReject(t *testing.T) {
	smContext := newGSMTestContext()

	golden := []byte{0x2e, 0x0a, 0x01, 0xc3, 0x26}

	got, err := BuildGSMPDUSessionEstablishmentReject(smContext, nasMessage.Cause5GSMNetworkFailure)
	require.NoError(t, err)

	// double-encode guard: same fixture must yield identical bytes
	got2, err := BuildGSMPDUSessionEstablishmentReject(smContext, nasMessage.Cause5GSMNetworkFailure)
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	// decode-back check
	m := nas.NewMessage()
	require.NoError(t, m.GsmMessageDecode(&golden))
	require.Equal(t, nas.MsgTypePDUSessionEstablishmentReject, m.GsmHeader.GetMessageType())
	require.Equal(t, uint8(1), m.PDUSessionEstablishmentReject.GetPTI())
	require.Equal(t, uint8(10), m.PDUSessionEstablishmentReject.GetPDUSessionID())
	require.Equal(t, nasMessage.Cause5GSMNetworkFailure, m.PDUSessionEstablishmentReject.GetCauseValue())
}

func TestGoldenBuildGSMPDUSessionReleaseCommand(t *testing.T) {
	testCases := []struct {
		name            string
		isTriggeredByUE bool
		wantPTI         uint8
		golden          []byte
	}{
		{
			name:            "TriggeredByUE",
			isTriggeredByUE: true,
			wantPTI:         1,
			golden:          []byte{0x2e, 0x0a, 0x01, 0xd3, 0x24},
		},
		{
			name:            "TriggeredByNetwork",
			isTriggeredByUE: false,
			wantPTI:         0,
			golden:          []byte{0x2e, 0x0a, 0x00, 0xd3, 0x24},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smContext := newGSMTestContext()

			got, err := BuildGSMPDUSessionReleaseCommand(
				smContext, nasMessage.Cause5GSMRegularDeactivation, tc.isTriggeredByUE)
			require.NoError(t, err)

			got2, err := BuildGSMPDUSessionReleaseCommand(
				smContext, nasMessage.Cause5GSMRegularDeactivation, tc.isTriggeredByUE)
			require.NoError(t, err)
			require.Equal(t, got, got2)

			require.Equal(t, tc.golden, got)

			m := nas.NewMessage()
			golden := tc.golden
			require.NoError(t, m.GsmMessageDecode(&golden))
			require.Equal(t, nas.MsgTypePDUSessionReleaseCommand, m.GsmHeader.GetMessageType())
			require.Equal(t, tc.wantPTI, m.PDUSessionReleaseCommand.GetPTI())
			require.Equal(t, uint8(10), m.PDUSessionReleaseCommand.GetPDUSessionID())
			require.Equal(t, nasMessage.Cause5GSMRegularDeactivation,
				m.PDUSessionReleaseCommand.GetCauseValue())
		})
	}
}

func TestGoldenBuildGSMPDUSessionModificationCommand(t *testing.T) {
	smContext := newGSMTestContext()

	golden := []byte{0x2e, 0x0a, 0x01, 0xcb}

	got, err := BuildGSMPDUSessionModificationCommand(smContext)
	require.NoError(t, err)

	got2, err := BuildGSMPDUSessionModificationCommand(smContext)
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	m := nas.NewMessage()
	require.NoError(t, m.GsmMessageDecode(&golden))
	require.Equal(t, nas.MsgTypePDUSessionModificationCommand, m.GsmHeader.GetMessageType())
	require.Equal(t, uint8(1), m.PDUSessionModificationCommand.GetPTI())
	require.Equal(t, uint8(10), m.PDUSessionModificationCommand.GetPDUSessionID())
}

func TestGoldenBuildGSMPDUSessionReleaseReject(t *testing.T) {
	smContext := newGSMTestContext()

	golden := []byte{0x2e, 0x0a, 0x01, 0xd2, 0x1f}

	got, err := BuildGSMPDUSessionReleaseReject(smContext)
	require.NoError(t, err)

	got2, err := BuildGSMPDUSessionReleaseReject(smContext)
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	m := nas.NewMessage()
	require.NoError(t, m.GsmMessageDecode(&golden))
	require.Equal(t, nas.MsgTypePDUSessionReleaseReject, m.GsmHeader.GetMessageType())
	require.Equal(t, uint8(1), m.PDUSessionReleaseReject.GetPTI())
	require.Equal(t, uint8(10), m.PDUSessionReleaseReject.GetPDUSessionID())
	require.Equal(t, nasMessage.Cause5GSMRequestRejectedUnspecified,
		m.PDUSessionReleaseReject.GetCauseValue())
}

func TestGoldenBuildGSMPDUSessionModificationReject(t *testing.T) {
	smContext := newGSMTestContext()

	golden := []byte{0x2e, 0x0a, 0x01, 0xca, 0x61}

	got, err := BuildGSMPDUSessionModificationReject(smContext)
	require.NoError(t, err)

	got2, err := BuildGSMPDUSessionModificationReject(smContext)
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	m := nas.NewMessage()
	require.NoError(t, m.GsmMessageDecode(&golden))
	require.Equal(t, nas.MsgTypePDUSessionModificationReject, m.GsmHeader.GetMessageType())
	require.Equal(t, uint8(1), m.PDUSessionModificationReject.GetPTI())
	require.Equal(t, uint8(10), m.PDUSessionModificationReject.GetPDUSessionID())
	require.Equal(t, nasMessage.Cause5GSMMessageTypeNonExistentOrNotImplemented,
		m.PDUSessionModificationReject.GetCauseValue())
}
