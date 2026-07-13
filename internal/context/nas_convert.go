package context

import (
	nasie "github.com/free5gc/nas/ie"
	"github.com/free5gc/openapi/models"
)

// ModelsToPDUSessionType maps an openapi PDU session type to the NAS encoded
// value (TS 24.501 9.11.4.11). It replaces the removed nasConvert helper.
func ModelsToPDUSessionType(pduSessType models.PduSessionType) uint8 {
	switch pduSessType {
	case models.PduSessionType_IPV4:
		return nasie.PDUSessType_IPv4
	case models.PduSessionType_IPV6:
		return nasie.PDUSessType_IPv6
	case models.PduSessionType_IPV4_V6:
		return nasie.PDUSessType_IPv4v6
	case models.PduSessionType_UNSTRUCTURED:
		return nasie.PDUSessType_Unstructured
	case models.PduSessionType_ETHERNET:
		return nasie.PDUSessType_Ethernet
	default:
		return nasie.PDUSessType_IPv4
	}
}

// PDUSessionTypeToModels maps a NAS encoded PDU session type back to the
// openapi model value. It replaces the removed nasConvert helper.
func PDUSessionTypeToModels(nasPduSessType uint8) models.PduSessionType {
	switch nasPduSessType {
	case nasie.PDUSessType_IPv4:
		return models.PduSessionType_IPV4
	case nasie.PDUSessType_IPv6:
		return models.PduSessionType_IPV6
	case nasie.PDUSessType_IPv4v6:
		return models.PduSessionType_IPV4_V6
	case nasie.PDUSessType_Unstructured:
		return models.PduSessionType_UNSTRUCTURED
	case nasie.PDUSessType_Ethernet:
		return models.PduSessionType_ETHERNET
	default:
		return ""
	}
}
