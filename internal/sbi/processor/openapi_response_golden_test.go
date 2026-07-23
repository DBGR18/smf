package processor_test

import (
	"mime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

const (
	testJSONMediaType      = "application/json"
	testMultipartMediaType = "multipart/related"
)

// extractBoundary pulls the random boundary out of a Serialize content type.
//
// The boundary must be parsed, not sliced off a fixed prefix: openapi builds
// the header with mime.FormatMediaType, which only quotes the value when it is
// not a valid HTTP token. openapi's generateBoundary draws from a charset that
// includes both token and non-token characters ("(),/:=?"), so the header is
// usually `boundary="..."` but is `boundary=...` whenever the random boundary
// happens to contain token characters only — a few percent of runs.
func extractBoundary(t *testing.T, contentType string) string {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	require.Equal(t, testMultipartMediaType, mediaType)
	boundary := params["boundary"]
	require.NotEmpty(t, boundary)
	return boundary
}

// goldenSmContextUpdatedDataJSON is the golden JSON encoding of newTestSmContextUpdatedData.
const goldenSmContextUpdatedDataJSON = `{"upCnxState":"DEACTIVATED",` +
	`"n1SmMsg":{"contentId":"PDUSessionReleaseCommand"},` +
	`"n2SmInfo":{"contentId":"PDUResourceReleaseCommand"},` +
	`"n2SmInfoType":"PDU_RES_REL_CMD"}`

// newTestSmContextUpdatedData mirrors the UpdateSmContext 200 response the SMF
// builds on the PDU session release path
// (internal/sbi/processor/pdu_session.go, HandlePDUSessionSMContextUpdate).
func newTestSmContextUpdatedData() *models.Smf_PDUSess_SmContextUpdatedData {
	return &models.Smf_PDUSess_SmContextUpdatedData{
		UpCnxState:   models.Smf_PDUSess_UpCnxState_DEACTIVATED,
		N1SmMsg:      &models.RefToBinaryData{ContentId: "PDUSessionReleaseCommand"},
		N2SmInfoType: models.Smf_PDUSess_N2SmInfoType_PDU_RES_REL_CMD,
		N2SmInfo:     &models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"},
	}
}

func TestGoldenSmContextCreatedDataJSON(t *testing.T) {
	// shape of SMContext.BuildCreatedData (internal/context/sm_context.go),
	// the JsonData of the PostSmContexts 201 response
	newCreatedData := func() *models.Smf_PDUSess_SmContextCreatedData {
		return &models.Smf_PDUSess_SmContextCreatedData{
			SNssai: &models.Snssai{Sst: 1, Sd: "112232"},
		}
	}

	golden := `{"sNssai":{"sst":1,"sd":"112232"}}`

	_, b, err := openapi.Serialize(newCreatedData(), testJSONMediaType)
	require.NoError(t, err)

	// double-encode guard
	_, b2, err := openapi.Serialize(newCreatedData(), testJSONMediaType)
	require.NoError(t, err)
	require.Equal(t, b, b2)

	require.Equal(t, golden, string(b))

	// decode-back check
	var decoded models.Smf_PDUSess_SmContextCreatedData
	require.NoError(t, openapi.Deserialize(&decoded, []byte(golden), testJSONMediaType))
	require.Equal(t, *newCreatedData(), decoded)
}

func TestGoldenSmContextUpdatedDataJSON(t *testing.T) {
	_, b, err := openapi.Serialize(newTestSmContextUpdatedData(), testJSONMediaType)
	require.NoError(t, err)

	// double-encode guard
	_, b2, err := openapi.Serialize(newTestSmContextUpdatedData(), testJSONMediaType)
	require.NoError(t, err)
	require.Equal(t, b, b2)

	require.Equal(t, goldenSmContextUpdatedDataJSON, string(b))

	// decode-back check
	var decoded models.Smf_PDUSess_SmContextUpdatedData
	require.NoError(t, openapi.Deserialize(&decoded, []byte(goldenSmContextUpdatedDataJSON), testJSONMediaType))
	require.Equal(t, *newTestSmContextUpdatedData(), decoded)
}

func TestGoldenUpdateSmContextResponse200Multipart(t *testing.T) {
	newResponse := func() models.UpdateSmContextResponse200 {
		return models.UpdateSmContextResponse200{
			JsonData: newTestSmContextUpdatedData(),
			// golden bytes of BuildGSMPDUSessionReleaseCommand (network-triggered)
			// (internal/context/gsm_build_internal_test.go)
			BinaryDataN1SmMessage: &multipart.RelatedContent{
				ContentID: "PDUSessionReleaseCommand", Content: []byte{0x2e, 0x0a, 0x00, 0xd3, 0x24},
			},
			// golden bytes of BuildPDUSessionResourceReleaseCommandTransfer
			// (internal/context/ngap_build_internal_test.go)
			BinaryDataN2SmInformation: &multipart.RelatedContent{ContentID: "PDUResourceReleaseCommand", Content: []byte{0x10}},
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
	contentType, body, err := openapi.Serialize(&resp, testMultipartMediaType)
	require.NoError(t, err)

	// the multipart boundary is random: normalize it before comparing.
	// The server render path calls the same openapi.Serialize, so this test
	// covers the response wire format.
	boundary := extractBoundary(t, contentType)
	norm := strings.ReplaceAll(string(body), boundary, "BOUNDARY")

	// double-encode guard (on normalized output: only the boundary may differ)
	resp2 := newResponse()
	contentType2, body2, err := openapi.Serialize(&resp2, testMultipartMediaType)
	require.NoError(t, err)
	boundary2 := extractBoundary(t, contentType2)
	require.Equal(t, norm, strings.ReplaceAll(string(body2), boundary2, "BOUNDARY"))

	require.Equal(t, golden, norm)

	// decode-back round-trip
	var decoded models.UpdateSmContextResponse200
	require.NoError(t, openapi.Deserialize(&decoded, body, contentType))
	require.Equal(t, resp, decoded)
}
