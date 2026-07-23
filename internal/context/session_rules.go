package context

import (
	"github.com/free5gc/openapi/models"
)

// SessionRule - A session rule consists of policy information elements
// associated with PDU session.
type SessionRule struct {
	*models.Pcf_SMPolCtrl_SessionRule
	DefQosQFI uint8
}

// NewSessionRule - create session rule from OpenAPI models
func NewSessionRule(model *models.Pcf_SMPolCtrl_SessionRule) *SessionRule {
	if model == nil {
		return nil
	}

	return &SessionRule{
		Pcf_SMPolCtrl_SessionRule: model,
		DefQosQFI:                 1,
	}
}
