package context

import (
	nasie "github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"
	ngapie "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/internal/util"
)

// QoSFlow  - Policy and Charging Rule

type QoSFlowState int

const (
	QoSFlowUnset QoSFlowState = iota
	QoSFlowSet
	QoSFlowToBeModify
)

type QoSFlow struct {
	QFI        uint8
	QoSProfile *models.Pcf_SMPolCtrl_QosData
	State      QoSFlowState
}

func NewQoSFlow(qfi uint8, qosModel *models.Pcf_SMPolCtrl_QosData) *QoSFlow {
	if qosModel == nil {
		return nil
	}
	qos := &QoSFlow{
		QFI:        qfi,
		QoSProfile: qosModel,
		State:      QoSFlowUnset,
	}
	return qos
}

func (q *QoSFlow) GetQFI() uint8 {
	return q.QFI
}

func (q *QoSFlow) Get5QI() uint8 {
	return uint8(q.QoSProfile.Var5qi)
}

func (q *QoSFlow) GetQoSProfile() *models.Pcf_SMPolCtrl_QosData {
	return q.QoSProfile
}

func (q *QoSFlow) IsGBRFlow() bool {
	return isGBRFlow(q.QoSProfile)
}

func (q *QoSFlow) BuildNasQoSDesc(opCode nasie.QfdOpCode) (nasie.QosFlowDesc, error) {
	qosDesc := nasie.QosFlowDesc{
		QFI:    q.GetQFI(),
		OpCode: opCode,
		EBit:   nasie.QfdEbit_HasParamList,
		FiveQI: uint8(q.QoSProfile.Var5qi),
	}

	if q.IsGBRFlow() && q.QoSProfile != nil {
		qosDesc.GFBRDownlink = q.QoSProfile.GbrDl
		qosDesc.GFBRUplink = q.QoSProfile.GbrUl
		qosDesc.MFBRDownlink = q.QoSProfile.MaxbrDl
		qosDesc.MFBRUplink = q.QoSProfile.MaxbrUl
	}
	return qosDesc, nil
}

func buildArpFromModels(arp *models.Arp) (int64, aper.Enumerated, aper.Enumerated) {
	if arp == nil {
		return 0, 0, 0
	}
	var arpPriorityLevel int64
	var arpPreEmptionCapability aper.Enumerated
	var arpPreEmptionVulnerability aper.Enumerated

	arpPriorityLevel = int64(arp.PriorityLevel)
	switch arp.PreemptCap {
	case models.PreemptionCapability_NOT_PREEMPT:
		arpPreEmptionCapability = ngapie.PreEmptionCapabilityPresentShallNotTriggerPreEmption
	case models.PreemptionCapability_MAY_PREEMPT:
		arpPreEmptionCapability = ngapie.PreEmptionCapabilityPresentMayTriggerPreEmption
	default:
		arpPreEmptionCapability = ngapie.PreEmptionCapabilityPresentShallNotTriggerPreEmption
	}
	switch arp.PreemptVuln {
	case models.PreemptionVulnerability_NOT_PREEMPTABLE:
		arpPreEmptionVulnerability = ngapie.PreEmptionVulnerabilityPresentNotPreEmptable
	case models.PreemptionVulnerability_PREEMPTABLE:
		arpPreEmptionVulnerability = ngapie.PreEmptionVulnerabilityPresentPreEmptable
	default:
		arpPreEmptionVulnerability = ngapie.PreEmptionVulnerabilityPresentNotPreEmptable
	}

	return arpPriorityLevel, arpPreEmptionCapability, arpPreEmptionVulnerability
}

func buildGBRQosInformationFromModel(qos *models.Pcf_SMPolCtrl_QosData) *ngapie.GBRQosInformation {
	if qos == nil {
		return nil
	}
	maxFlowBitRateDL := util.StringToBitRate(qos.MaxbrDl)
	maxFlowBitRateUL := util.StringToBitRate(qos.MaxbrUl)
	guaranteedFlowBitRateDL := util.StringToBitRate(qos.GbrDl)
	guaranteedFlowBitRateUL := util.StringToBitRate(qos.GbrUl)
	return &ngapie.GBRQosInformation{
		MaximumFlowBitRateDL:    &maxFlowBitRateDL,
		MaximumFlowBitRateUL:    &maxFlowBitRateUL,
		GuaranteedFlowBitRateDL: &guaranteedFlowBitRateDL,
		GuaranteedFlowBitRateUL: &guaranteedFlowBitRateUL,
	}
}

func (q *QoSFlow) buildNgapQosFlowLevelQosParameters() *ngapie.QosFlowLevelQosParameters {
	parameter := &ngapie.QosFlowLevelQosParameters{
		QosCharacteristics: &ngapie.QosCharacteristics{
			Choice: &ngapie.NonDynamic5QIDescriptor{
				FiveQI: &ngapie.FiveQI{
					Value: int64(q.Get5QI()),
				},
			},
		},
	}

	if q.IsGBRFlow() {
		parameter.GBRQosInformation = buildGBRQosInformationFromModel(q.QoSProfile)
	}

	var arpPriorityLevel int64
	var arpPreEmptionCapability aper.Enumerated
	var arpPreEmptionVulnerability aper.Enumerated
	if arp := q.QoSProfile.Arp; arp != nil {
		arpPriorityLevel,
			arpPreEmptionCapability,
			arpPreEmptionVulnerability = buildArpFromModels(arp)
	} else {
		// TODO: should get value from PCF
		arpPriorityLevel = 8
		arpPreEmptionCapability = ngapie.PreEmptionCapabilityPresentShallNotTriggerPreEmption
		arpPreEmptionVulnerability = ngapie.PreEmptionVulnerabilityPresentNotPreEmptable
	}

	parameter.AllocationAndRetentionPriority = &ngapie.AllocationAndRetentionPriority{
		PriorityLevelARP: &ngapie.PriorityLevelARP{
			Value: arpPriorityLevel,
		},
		PreEmptionCapability: &ngapie.PreEmptionCapability{
			Value: arpPreEmptionCapability,
		},
		PreEmptionVulnerability: &ngapie.PreEmptionVulnerability{
			Value: arpPreEmptionVulnerability,
		},
	}

	return parameter
}

func (q *QoSFlow) BuildNgapQosFlowSetupRequestItem() (ngapie.QosFlowSetupRequestItem, error) {
	qosDesc := ngapie.QosFlowSetupRequestItem{
		QosFlowIdentifier: &ngapie.QosFlowIdentifier{
			Value: int64(q.GetQFI()),
		},
		QosFlowLevelQosParameters: q.buildNgapQosFlowLevelQosParameters(),
	}
	return qosDesc, nil
}

func (q *QoSFlow) BuildNgapQosFlowAddOrModifyRequestItem() (ngapie.QosFlowAddOrModifyRequestItem, error) {
	qosDesc := ngapie.QosFlowAddOrModifyRequestItem{
		QosFlowIdentifier: &ngapie.QosFlowIdentifier{
			Value: int64(q.GetQFI()),
		},
		QosFlowLevelQosParameters: q.buildNgapQosFlowLevelQosParameters(),
	}
	return qosDesc, nil
}
