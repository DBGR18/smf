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
