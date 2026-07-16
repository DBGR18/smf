package context

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/pkg/factory"
)

// newTestUPTunnel builds a deterministic single-path UPTunnel: exactly one
// default data path so DataPathPool map iteration cannot affect the output.
func newTestUPTunnel() *UPTunnel {
	upf := NewUPF(
		&pfcpType.NodeID{NodeIdType: pfcpType.NodeIdTypeIpv4Address, IP: net.ParseIP("192.168.179.1").To4()},
		[]*factory.InterfaceUpfInfoItem{{
			InterfaceType:    models.UpInterfaceType_N3,
			Endpoints:        []string{"127.0.0.8"},
			NetworkInstances: []string{"internet"},
		}})
	node := NewDataPathNode() // non-nil Up/DownLinkTunnel
	node.UPF = upf
	node.UpLinkTunnel.TEID = 0x1001
	dp := NewDataPath()
	dp.FirstDPNode = node
	dp.IsDefaultPath = true
	dp.Activated = true
	tunnel := NewUPTunnel()
	tunnel.DataPathPool[1] = dp // fixed key; PathID is never encoded
	return tunnel
}

func TestGoldenBuildPathSwitchRequestUnsuccessfulTransfer(t *testing.T) {
	golden := []byte{0x00, 0x00}

	got, err := BuildPathSwitchRequestUnsuccessfulTransfer(
		ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)
	require.NoError(t, err)

	// double-encode guard
	got2, err := BuildPathSwitchRequestUnsuccessfulTransfer(
		ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	// decode-back check
	var decoded ngapType.PathSwitchRequestUnsuccessfulTransfer
	require.NoError(t, aper.UnmarshalWithParams(golden, &decoded, "valueExt"))
	require.Equal(t, ngapType.CausePresentRadioNetwork, decoded.Cause.Present)
	require.NotNil(t, decoded.Cause.RadioNetwork)
	require.Equal(t, ngapType.CauseRadioNetworkPresentUnspecified, decoded.Cause.RadioNetwork.Value)
}

func TestGoldenBuildPDUSessionResourceReleaseCommandTransfer(t *testing.T) {
	golden := []byte{0x10}

	got, err := BuildPDUSessionResourceReleaseCommandTransfer(&SMContext{}) // ctx is unused
	require.NoError(t, err)

	got2, err := BuildPDUSessionResourceReleaseCommandTransfer(&SMContext{})
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	var decoded ngapType.PDUSessionResourceReleaseCommandTransfer
	require.NoError(t, aper.UnmarshalWithParams(golden, &decoded, "valueExt"))
	require.Equal(t, ngapType.CausePresentNas, decoded.Cause.Present)
	require.NotNil(t, decoded.Cause.Nas)
	require.Equal(t, ngapType.CauseNasPresentNormalRelease, decoded.Cause.Nas.Value)
}

func TestGoldenBuildPDUSessionResourceModifyRequestTransfer(t *testing.T) {
	newModifyContext := func() *SMContext {
		smContext := newGSMTestContext()
		// exactly ONE flow: QosFlowAddOrModifyRequestList has aper tag sizeLB:1,
		// and two or more map entries would make the encoding order unstable
		smContext.AdditionalQosFlows = map[uint8]*QoSFlow{
			2: NewQoSFlow(2, &models.QosData{
				Var5qi: 9,
				Arp: &models.Arp{
					PriorityLevel: 8,
					PreemptCap:    models.PreemptionCapability_NOT_PREEMPT,
					PreemptVuln:   models.PreemptionVulnerability_NOT_PREEMPTABLE,
				},
			}),
		}
		return smContext
	}

	golden := []byte{0x00, 0x00, 0x01, 0x00, 0x87, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0x09, 0x1c, 0x00}

	got, err := BuildPDUSessionResourceModifyRequestTransfer(newModifyContext())
	require.NoError(t, err)

	got2, err := BuildPDUSessionResourceModifyRequestTransfer(newModifyContext())
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	var decoded ngapType.PDUSessionResourceModifyRequestTransfer
	require.NoError(t, aper.UnmarshalWithParams(golden, &decoded, "valueExt"))
	require.Len(t, decoded.ProtocolIEs.List, 1)
	qosList := decoded.ProtocolIEs.List[0].Value.QosFlowAddOrModifyRequestList
	require.NotNil(t, qosList)
	require.Len(t, qosList.List, 1)
	require.Equal(t, int64(2), qosList.List[0].QosFlowIdentifier.Value)
}

func TestGoldenBuildPDUSessionResourceModifyConfirmTransfer(t *testing.T) {
	newConfirmTunnel := func() *UPTunnel {
		tunnel := newTestUPTunnel()
		node := tunnel.DataPathPool.GetDefaultPath().FirstDPNode
		// Precedence must not be 255 (default flow is skipped by the builder)
		node.DownLinkTunnel.PDR = &PDR{
			Precedence: 100,
			QER:        []*QER{{QFI: pfcpType.QFI{QFI: 2}}},
		}
		return tunnel
	}

	golden := []byte{0x00, 0x00, 0x40, 0x3e, 0xc0, 0xa8, 0xb3, 0x01, 0x00, 0x00, 0x01, 0x03}

	got, err := BuildPDUSessionResourceModifyConfirmTransfer(newGSMTestContext(), newConfirmTunnel(), 0x00000103)
	require.NoError(t, err)

	got2, err := BuildPDUSessionResourceModifyConfirmTransfer(newGSMTestContext(), newConfirmTunnel(), 0x00000103)
	require.NoError(t, err)
	require.Equal(t, got, got2)

	require.Equal(t, golden, got)

	var decoded ngapType.PDUSessionResourceModifyConfirmTransfer
	require.NoError(t, aper.UnmarshalWithParams(golden, &decoded, "valueExt"))
	require.Len(t, decoded.QosFlowModifyConfirmList.List, 1)
	require.Equal(t, int64(2), decoded.QosFlowModifyConfirmList.List[0].QosFlowIdentifier.Value)
	require.NotNil(t, decoded.ULNGUUPTNLInformation.GTPTunnel)
	require.Equal(t, aper.OctetString{0x00, 0x00, 0x01, 0x03}, decoded.ULNGUUPTNLInformation.GTPTunnel.GTPTEID.Value)
	require.Equal(t, []byte(net.ParseIP("192.168.179.1").To4()),
		decoded.ULNGUUPTNLInformation.GTPTunnel.TransportLayerAddress.Value.Bytes)
}

func TestGoldenBuildPDUSessionResourceSetupRequestTransfer(t *testing.T) {
	newSetupContext := func(withUpSecurity bool) func() *SMContext {
		return func() *SMContext {
			smContext := newGSMTestContext()
			smContext.Tunnel = newTestUPTunnel()
			// fixed values: NewSMContext would pull these from the global
			// TeidGenerator, which is test-order dependent
			smContext.LocalULTeid = 0x00000101
			smContext.LocalULTeidForSplitPDUSession = 0x00000102
			if withUpSecurity {
				smContext.UpSecurity = &models.UpSecurity{
					UpIntegr: models.UpIntegrity_REQUIRED,
					UpConfid: models.UpConfidentiality_REQUIRED,
				}
				maxUERate := models.MaxIntegrityProtectedDataRate_MAX_UE_RATE
				smContext.MaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink = maxUERate
			}
			return smContext
		}
	}

	newGBRSetupContext := func() *SMContext {
		smContext := newSetupContext(false)()
		// exactly ONE additional flow (map iteration order!) with a standard
		// GBR 5QI: exercises BuildNgapQosFlowSetupRequestItem and the
		// GBRQosInformation branch (bitrate-string conversion included)
		smContext.AdditionalQosFlows = map[uint8]*QoSFlow{
			2: NewQoSFlow(2, &models.QosData{
				Var5qi:  1,
				GbrDl:   "100 Mbps",
				GbrUl:   "50 Mbps",
				MaxbrDl: "200 Mbps",
				MaxbrUl: "150 Mbps",
				Arp: &models.Arp{
					PriorityLevel: 8,
					PreemptCap:    models.PreemptionCapability_NOT_PREEMPT,
					PreemptVuln:   models.PreemptionVulnerability_NOT_PREEMPTABLE,
				},
			}),
		}
		return smContext
	}

	testCases := []struct {
		name           string
		setupContext   func() *SMContext
		withUpSecurity bool
		wantIEs        int
		wantQosFlows   int
		golden         []byte
	}{
		{
			name:           "WithoutUpSecurity",
			setupContext:   newSetupContext(false),
			withUpSecurity: false,
			wantIEs:        5,
			wantQosFlows:   1,
			golden: []byte{
				0x00, 0x00, 0x05, 0x00, 0x82, 0x00, 0x08, 0x08, 0x01, 0x86, 0xa0, 0x20,
				0x03, 0x0d, 0x40, 0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x7f, 0x00, 0x00,
				0x08, 0x00, 0x00, 0x01, 0x01, 0x00, 0x7e, 0x40, 0x0a, 0x00, 0x1f, 0x7f,
				0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86, 0x00, 0x01, 0x00,
				0x00, 0x88, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x09, 0x1c, 0x00,
			},
		},
		{
			name:           "WithUpSecurity",
			setupContext:   newSetupContext(true),
			withUpSecurity: true,
			wantIEs:        6,
			wantQosFlows:   1,
			golden: []byte{
				0x00, 0x00, 0x06, 0x00, 0x82, 0x00, 0x08, 0x08, 0x01, 0x86, 0xa0, 0x20,
				0x03, 0x0d, 0x40, 0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x7f, 0x00, 0x00,
				0x08, 0x00, 0x00, 0x01, 0x01, 0x00, 0x7e, 0x40, 0x0a, 0x00, 0x1f, 0x7f,
				0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86, 0x00, 0x01, 0x00,
				0x00, 0x88, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x09, 0x1c, 0x00, 0x00,
				0x8a, 0x00, 0x02, 0x40, 0x20,
			},
		},
		{
			name:           "WithGBRAdditionalQosFlow",
			setupContext:   newGBRSetupContext,
			withUpSecurity: false,
			wantIEs:        5,
			wantQosFlows:   2,
			golden: []byte{
				0x00, 0x00, 0x05, 0x00, 0x82, 0x00, 0x08, 0x08, 0x01, 0x86, 0xa0, 0x20,
				0x03, 0x0d, 0x40, 0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x7f, 0x00, 0x00,
				0x08, 0x00, 0x00, 0x01, 0x01, 0x00, 0x7e, 0x40, 0x0a, 0x00, 0x1f, 0x7f,
				0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86, 0x00, 0x01, 0x00,
				0x00, 0x88, 0x00, 0x21, 0x04, 0x01, 0x00, 0x00, 0x09, 0x1c, 0x00, 0x24,
				0x00, 0x00, 0x01, 0x1c, 0x00, 0x60, 0x0b, 0xeb, 0xc2, 0x00, 0x30, 0x08,
				0xf0, 0xd1, 0x80, 0x30, 0x05, 0xf5, 0xe1, 0x00, 0x30, 0x02, 0xfa, 0xf0,
				0x80,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildPDUSessionResourceSetupRequestTransfer(tc.setupContext())
			require.NoError(t, err)

			got2, err := BuildPDUSessionResourceSetupRequestTransfer(tc.setupContext())
			require.NoError(t, err)
			require.Equal(t, got, got2)

			require.Equal(t, tc.golden, got)

			var decoded ngapType.PDUSessionResourceSetupRequestTransfer
			require.NoError(t, aper.UnmarshalWithParams(tc.golden, &decoded, "valueExt"))
			require.Len(t, decoded.ProtocolIEs.List, tc.wantIEs)

			var gotTEID aper.OctetString
			var gotSecurity *ngapType.SecurityIndication
			var gotQosList *ngapType.QosFlowSetupRequestList
			for _, ie := range decoded.ProtocolIEs.List {
				switch ie.Id.Value {
				case ngapType.ProtocolIEIDULNGUUPTNLInformation:
					gotTEID = ie.Value.ULNGUUPTNLInformation.GTPTunnel.GTPTEID.Value
				case ngapType.ProtocolIEIDSecurityIndication:
					gotSecurity = ie.Value.SecurityIndication
				case ngapType.ProtocolIEIDQosFlowSetupRequestList:
					gotQosList = ie.Value.QosFlowSetupRequestList
				}
			}
			require.Equal(t, aper.OctetString{0x00, 0x00, 0x01, 0x01}, gotTEID)
			require.NotNil(t, gotQosList)
			require.Len(t, gotQosList.List, tc.wantQosFlows)
			if tc.wantQosFlows > 1 {
				gbrItem := gotQosList.List[1]
				require.Equal(t, int64(2), gbrItem.QosFlowIdentifier.Value)
				gbrInfo := gbrItem.QosFlowLevelQosParameters.GBRQosInformation
				require.NotNil(t, gbrInfo)
				require.Equal(t, int64(200000000), gbrInfo.MaximumFlowBitRateDL.Value)
				require.Equal(t, int64(150000000), gbrInfo.MaximumFlowBitRateUL.Value)
				require.Equal(t, int64(100000000), gbrInfo.GuaranteedFlowBitRateDL.Value)
				require.Equal(t, int64(50000000), gbrInfo.GuaranteedFlowBitRateUL.Value)
			}
			if tc.withUpSecurity {
				require.NotNil(t, gotSecurity)
				require.Equal(t, ngapType.IntegrityProtectionIndicationPresentRequired,
					gotSecurity.IntegrityProtectionIndication.Value)
				require.Equal(t, ngapType.ConfidentialityProtectionIndicationPresentRequired,
					gotSecurity.ConfidentialityProtectionIndication.Value)
				require.NotNil(t, gotSecurity.MaximumIntegrityProtectedDataRateUL)
				require.Equal(t, ngapType.MaximumIntegrityProtectedDataRatePresentMaximumUERate,
					gotSecurity.MaximumIntegrityProtectedDataRateUL.Value)
			} else {
				require.Nil(t, gotSecurity)
			}
		})
	}
}

func TestGoldenBuildPathSwitchRequestAcknowledgeTransfer(t *testing.T) {
	newAckContext := func(sameAsLocalStored bool) func() *SMContext {
		return func() *SMContext {
			smContext := newGSMTestContext()
			smContext.Tunnel = newTestUPTunnel()
			smContext.UpSecurityFromPathSwitchRequestSameAsLocalStored = sameAsLocalStored
			if !sameAsLocalStored {
				// the false (zero-value!) branch dereferences ctx.UpSecurity:
				// it MUST be set or the builder panics
				smContext.UpSecurity = &models.UpSecurity{
					UpIntegr: models.UpIntegrity_REQUIRED,
					UpConfid: models.UpConfidentiality_REQUIRED,
				}
				maxUERate := models.MaxIntegrityProtectedDataRate_MAX_UE_RATE
				smContext.MaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink = maxUERate
			}
			return smContext
		}
	}

	testCases := []struct {
		name              string
		setupContext      func() *SMContext
		wantSecurityIndic bool
		golden            []byte
	}{
		{
			name:              "SecuritySameAsLocalStored",
			setupContext:      newAckContext(true),
			wantSecurityIndic: false,
			golden: []byte{
				0x40, 0x1f, 0x7f, 0x00, 0x00, 0x08, 0x00, 0x00, 0x10, 0x01,
			},
		},
		{
			name:              "SecurityMismatch",
			setupContext:      newAckContext(false),
			wantSecurityIndic: true,
			golden: []byte{
				0x60, 0x1f, 0x7f, 0x00, 0x00, 0x08, 0x00, 0x00, 0x10, 0x01, 0x40, 0x20,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildPathSwitchRequestAcknowledgeTransfer(tc.setupContext())
			require.NoError(t, err)

			got2, err := BuildPathSwitchRequestAcknowledgeTransfer(tc.setupContext())
			require.NoError(t, err)
			require.Equal(t, got, got2)

			require.Equal(t, tc.golden, got)

			var decoded ngapType.PathSwitchRequestAcknowledgeTransfer
			require.NoError(t, aper.UnmarshalWithParams(tc.golden, &decoded, "valueExt"))
			require.NotNil(t, decoded.ULNGUUPTNLInformation)
			gtpTunnel := decoded.ULNGUUPTNLInformation.GTPTunnel
			require.NotNil(t, gtpTunnel)
			require.Equal(t, aper.OctetString{0x00, 0x00, 0x10, 0x01}, gtpTunnel.GTPTEID.Value)
			require.Equal(t, []byte(net.ParseIP("127.0.0.8").To4()),
				gtpTunnel.TransportLayerAddress.Value.Bytes)
			if tc.wantSecurityIndic {
				require.NotNil(t, decoded.SecurityIndication)
				require.Equal(t, ngapType.IntegrityProtectionIndicationPresentRequired,
					decoded.SecurityIndication.IntegrityProtectionIndication.Value)
			} else {
				require.Nil(t, decoded.SecurityIndication)
			}
		})
	}
}

func TestGoldenBuildHandoverCommandTransfer(t *testing.T) {
	newDirectContext := func() *SMContext {
		smContext := newGSMTestContext()
		// zero value of DLForwardingType is IndirectForwarding: ALWAYS set it
		smContext.DLForwardingType = DirectForwarding
		smContext.DLDirectForwardingTunnel = &ngapType.UPTransportLayerInformation{
			Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
			GTPTunnel: &ngapType.GTPTunnel{
				TransportLayerAddress: ngapType.TransportLayerAddress{
					Value: aper.BitString{
						Bytes:     net.ParseIP("127.0.0.10").To4(),
						BitLength: 32,
					},
				},
				GTPTEID: ngapType.GTPTEID{Value: aper.OctetString{0x00, 0x00, 0x01, 0x04}},
			},
		}
		return smContext
	}
	newIndirectContext := func() *SMContext {
		smContext := newGSMTestContext()
		smContext.DLForwardingType = IndirectForwarding
		smContext.Tunnel = newTestUPTunnel() // indirect branch reads the N3 IP from Tunnel's ANUPF
		node2 := NewDataPathNode()
		node2.UpLinkTunnel.TEID = 0x1002
		smContext.IndirectForwardingTunnel = &DataPath{FirstDPNode: node2}
		return smContext
	}

	testCases := []struct {
		name         string
		setupContext func() *SMContext
		wantTEID     aper.OctetString
		wantIP       string
		golden       []byte
	}{
		{
			name:         "DirectForwarding",
			setupContext: newDirectContext,
			wantTEID:     aper.OctetString{0x00, 0x00, 0x01, 0x04},
			wantIP:       "127.0.0.10",
			golden: []byte{
				0x60, 0x0f, 0x80, 0x7f, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x04, 0x00,
				0x12,
			},
		},
		{
			name:         "IndirectForwarding",
			setupContext: newIndirectContext,
			wantTEID:     aper.OctetString{0x00, 0x00, 0x10, 0x02},
			wantIP:       "127.0.0.8",
			golden: []byte{
				0x60, 0x0f, 0x80, 0x7f, 0x00, 0x00, 0x08, 0x00, 0x00, 0x10, 0x02, 0x00,
				0x12,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildHandoverCommandTransfer(tc.setupContext())
			require.NoError(t, err)

			got2, err := BuildHandoverCommandTransfer(tc.setupContext())
			require.NoError(t, err)
			require.Equal(t, got, got2)

			require.Equal(t, tc.golden, got)

			var decoded ngapType.HandoverCommandTransfer
			require.NoError(t, aper.UnmarshalWithParams(tc.golden, &decoded, "valueExt"))
			require.NotNil(t, decoded.DLForwardingUPTNLInformation)
			gtpTunnel := decoded.DLForwardingUPTNLInformation.GTPTunnel
			require.NotNil(t, gtpTunnel)
			require.Equal(t, tc.wantTEID, gtpTunnel.GTPTEID.Value)
			require.Equal(t, []byte(net.ParseIP(tc.wantIP).To4()),
				gtpTunnel.TransportLayerAddress.Value.Bytes)
			require.NotNil(t, decoded.QosFlowToBeForwardedList)
			require.Len(t, decoded.QosFlowToBeForwardedList.List, 1)
			require.Equal(t, int64(DefaultNonGBR5QI),
				decoded.QosFlowToBeForwardedList.List[0].QosFlowIdentifier.Value)
		})
	}
}
