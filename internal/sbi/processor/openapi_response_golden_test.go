package processor_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

const (
	testJSONMediaType     = "application/json"
	testMultipartCTPrefix = `multipart/related; boundary="`
)

// goldenSmContextUpdatedDataJSON is the golden JSON encoding of newTestSmContextUpdatedData.
const goldenSmContextUpdatedDataJSON = `{"upCnxState":"DEACTIVATED",` +
	`"n1SmMsg":{"contentId":"PDUSessionReleaseCommand"},` +
	`"n2SmInfo":{"contentId":"PDUResourceReleaseCommand"},` +
	`"n2SmInfoType":"PDU_RES_REL_CMD"}`

// newTestSmContextUpdatedData mirrors the UpdateSmContext 200 response the SMF
// builds on the PDU session release path
// (internal/sbi/processor/pdu_session.go, HandlePDUSessionSMContextUpdate).
func newTestSmContextUpdatedData() *models.SmContextUpdatedData {
	return &models.SmContextUpdatedData{
		UpCnxState:   models.UpCnxState_DEACTIVATED,
		N1SmMsg:      &models.RefToBinaryData{ContentId: "PDUSessionReleaseCommand"},
		N2SmInfoType: models.N2SmInfoType_PDU_RES_REL_CMD,
		N2SmInfo:     &models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"},
	}
}

func TestGoldenSmContextCreatedDataJSON(t *testing.T) {
	// shape of SMContext.BuildCreatedData (internal/context/sm_context.go),
	// the JsonData of the PostSmContexts 201 response
	newCreatedData := func() *models.SmfPduSessionSmContextCreatedData {
		return &models.SmfPduSessionSmContextCreatedData{
			SNssai: &models.Snssai{Sst: 1, Sd: "112232"},
		}
	}

	golden := `{"sNssai":{"sst":1,"sd":"112232"}}`

	b, err := openapi.Serialize(newCreatedData(), testJSONMediaType)
	require.NoError(t, err)

	// double-encode guard
	b2, err := openapi.Serialize(newCreatedData(), testJSONMediaType)
	require.NoError(t, err)
	require.Equal(t, b, b2)

	require.Equal(t, golden, string(b))

	// decode-back check
	var decoded models.SmfPduSessionSmContextCreatedData
	require.NoError(t, openapi.Deserialize(&decoded, []byte(golden), testJSONMediaType))
	require.Equal(t, *newCreatedData(), decoded)
}

func TestGoldenSmContextUpdatedDataJSON(t *testing.T) {
	b, err := openapi.Serialize(newTestSmContextUpdatedData(), testJSONMediaType)
	require.NoError(t, err)

	// double-encode guard
	b2, err := openapi.Serialize(newTestSmContextUpdatedData(), testJSONMediaType)
	require.NoError(t, err)
	require.Equal(t, b, b2)

	require.Equal(t, goldenSmContextUpdatedDataJSON, string(b))

	// decode-back check
	var decoded models.SmContextUpdatedData
	require.NoError(t, openapi.Deserialize(&decoded, []byte(goldenSmContextUpdatedDataJSON), testJSONMediaType))
	require.Equal(t, *newTestSmContextUpdatedData(), decoded)
}

func TestGoldenUpdateSmContextResponse200Multipart(t *testing.T) {
	newResponse := func() models.UpdateSmContextResponse200 {
		return models.UpdateSmContextResponse200{
			JsonData: newTestSmContextUpdatedData(),
			// golden bytes of BuildGSMPDUSessionReleaseCommand (network-triggered)
			// (internal/context/gsm_build_internal_test.go)
			BinaryDataN1SmMessage: []byte{0x2e, 0x0a, 0x00, 0xd3, 0x24},
			// golden bytes of BuildPDUSessionResourceReleaseCommandTransfer
			// (internal/context/ngap_build_internal_test.go)
			BinaryDataN2SmInformation: []byte{0x10},
		}
	}

	golden := strings.Join([]string{
		"--BOUNDARY",
		"Content-Type: application/json",
		"",
		goldenSmContextUpdatedDataJSON,
		"--BOUNDARY",
		"Content-Id: PDUSessionReleaseCommand",
		"Content-Type: application/vnd.3gpp.5gnas",
		"",
		"\x2e\x0a\x00\xd3\x24",
		"--BOUNDARY",
		"Content-Id: PDUResourceReleaseCommand",
		"Content-Type: application/vnd.3gpp.ngap",
		"",
		"\x10",
		"--BOUNDARY--",
		"",
	}, "\r\n")

	resp := newResponse()
	buf := &bytes.Buffer{}
	contentType, err := openapi.MultipartEncode(&resp, buf)
	require.NoError(t, err)

	// the multipart boundary is random: normalize it before comparing.
	// The server render path (openapi.MultipartRelatedRender) calls the same
	// MultipartEncode, so this test covers the response wire format.
	require.True(t, strings.HasPrefix(contentType, testMultipartCTPrefix))
	require.True(t, strings.HasSuffix(contentType, `"`))
	boundary := contentType[len(testMultipartCTPrefix) : len(contentType)-1]
	norm := strings.ReplaceAll(buf.String(), boundary, "BOUNDARY")

	// double-encode guard (on normalized output: only the boundary may differ)
	resp2 := newResponse()
	buf2 := &bytes.Buffer{}
	contentType2, err := openapi.MultipartEncode(&resp2, buf2)
	require.NoError(t, err)
	boundary2 := contentType2[len(testMultipartCTPrefix) : len(contentType2)-1]
	require.Equal(t, norm, strings.ReplaceAll(buf2.String(), boundary2, "BOUNDARY"))

	require.Equal(t, golden, norm)

	// decode-back round-trip
	var decoded models.UpdateSmContextResponse200
	require.NoError(t, openapi.Deserialize(&decoded, buf.Bytes(), contentType))
	require.Equal(t, resp, decoded)
}
