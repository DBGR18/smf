package consumer_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

const (
	testN1ContentID   = "GSM_NAS"
	testN2ContentID   = "N2SmInformation"
	jsonMediaType     = "application/json"
	multipartCTPrefix = `multipart/related; boundary="`
)

// goldenN1N2ReqDataJSON is the golden JSON encoding of newTestN1N2MessageTransferReqData.
const goldenN1N2ReqDataJSON = `{"n1MessageContainer":{"n1MessageClass":"SM",` +
	`"n1MessageContent":{"contentId":"GSM_NAS"}},` +
	`"n2InfoContainer":{"n2InformationClass":"SM","smInfo":{"pduSessionId":10,` +
	`"n2InfoContent":{"ngapIeType":"PDU_RES_SETUP_REQ",` +
	`"ngapData":{"contentId":"N2SmInformation"}},` +
	`"sNssai":{"sst":1,"sd":"112232"}}},"pduSessionId":10}`

// newTestN1N2MessageTransferReqData mirrors how the SMF fills the JsonData of
// N1N2MessageTransfer in sendPDUSessionEstablishmentAccept
// (internal/sbi/processor/datapath.go).
func newTestN1N2MessageTransferReqData() *models.N1N2MessageTransferReqData {
	return &models.N1N2MessageTransferReqData{
		PduSessionId: 10,
		N1MessageContainer: &models.N1MessageContainer{
			N1MessageClass:   "SM",
			N1MessageContent: &models.RefToBinaryData{ContentId: testN1ContentID},
		},
		N2InfoContainer: &models.N2InfoContainer{
			N2InformationClass: models.N2InformationClass_SM,
			SmInfo: &models.N2SmInformation{
				PduSessionId: 10,
				N2InfoContent: &models.N2InfoContent{
					NgapIeType: models.AmfCommunicationNgapIeType_PDU_RES_SETUP_REQ,
					NgapData: &models.RefToBinaryData{
						ContentId: testN2ContentID,
					},
				},
				SNssai: &models.Snssai{Sst: 1, Sd: "112232"},
			},
		},
	}
}

// extractBoundary pulls the random boundary out of a MultipartEncode content type.
func extractBoundary(t *testing.T, contentType string) string {
	t.Helper()
	require.True(t, strings.HasPrefix(contentType, multipartCTPrefix))
	require.True(t, strings.HasSuffix(contentType, `"`))
	return contentType[len(multipartCTPrefix) : len(contentType)-1]
}

func TestGoldenN1N2MessageTransferReqDataJSON(t *testing.T) {
	b, err := openapi.Serialize(newTestN1N2MessageTransferReqData(), jsonMediaType)
	require.NoError(t, err)

	// double-encode guard
	b2, err := openapi.Serialize(newTestN1N2MessageTransferReqData(), jsonMediaType)
	require.NoError(t, err)
	require.Equal(t, b, b2)

	require.Equal(t, goldenN1N2ReqDataJSON, string(b))

	// decode-back check
	var decoded models.N1N2MessageTransferReqData
	require.NoError(t, openapi.Deserialize(&decoded, []byte(goldenN1N2ReqDataJSON), jsonMediaType))
	require.Equal(t, *newTestN1N2MessageTransferReqData(), decoded)
}

func TestGoldenN1N2MessageTransferRequestMultipart(t *testing.T) {
	newRequest := func() models.N1N2MessageTransferRequest {
		return models.N1N2MessageTransferRequest{
			JsonData: newTestN1N2MessageTransferReqData(),
			// golden bytes of BuildGSMPDUSessionEstablishmentReject
			// (internal/context/gsm_build_internal_test.go)
			BinaryDataN1Message: []byte{0x2e, 0x0a, 0x01, 0xc3, 0x26},
			// golden bytes of BuildPDUSessionResourceModifyConfirmTransfer
			// (internal/context/ngap_build_internal_test.go)
			BinaryDataN2Information: []byte{
				0x00, 0x00, 0x40, 0x3e, 0xc0, 0xa8, 0xb3, 0x01, 0x00, 0x00, 0x01, 0x03,
			},
		}
	}

	golden := strings.Join([]string{
		"--BOUNDARY",
		"Content-Type: application/json",
		"",
		goldenN1N2ReqDataJSON,
		"--BOUNDARY",
		"Content-Id: GSM_NAS",
		"Content-Type: application/vnd.3gpp.5gnas",
		"",
		"\x2e\x0a\x01\xc3\x26",
		"--BOUNDARY",
		"Content-Id: N2SmInformation",
		"Content-Type: application/vnd.3gpp.ngap",
		"",
		"\x00\x00\x40\x3e\xc0\xa8\xb3\x01\x00\x00\x01\x03",
		"--BOUNDARY--",
		"",
	}, "\r\n")

	req := newRequest()
	buf := &bytes.Buffer{}
	contentType, err := openapi.MultipartEncode(&req, buf)
	require.NoError(t, err)

	// the multipart boundary is random: normalize it before comparing
	boundary := extractBoundary(t, contentType)
	norm := strings.ReplaceAll(buf.String(), boundary, "BOUNDARY")

	// double-encode guard (on normalized output: only the boundary may differ)
	req2 := newRequest()
	buf2 := &bytes.Buffer{}
	contentType2, err := openapi.MultipartEncode(&req2, buf2)
	require.NoError(t, err)
	boundary2 := extractBoundary(t, contentType2)
	require.Equal(t, norm, strings.ReplaceAll(buf2.String(), boundary2, "BOUNDARY"))

	require.Equal(t, golden, norm)

	// decode-back: same core path as the server side's multipart binding
	var decoded models.N1N2MessageTransferRequest
	require.NoError(t, openapi.Deserialize(&decoded, buf.Bytes(), contentType))
	require.Equal(t, req, decoded)
}
