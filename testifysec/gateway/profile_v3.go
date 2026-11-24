package main

import (
	"errors"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// Gateway v3 reads signed profile v3 (testifysec/managed/profile-v3.ts): the v1 assignment plus the
// marking this gateway is accredited for and the connectors the profile admits. The gateway refuses
// every request while an admitted connector's marking is above its accreditation (server.go).
const gatewayV3 = "testifysec.hardened-opencode.gateway/v3"

// An admitted connector's Notice is optional and never a marking. An explicit `"notice":null` is
// refused, not read as absent: strictTyped compares the raw object with the canonical encoding, in
// which a nil Notice is omitted, so the null leaves a key the canonical form lacks
// (profile_v3_test.go, "notice-null").
type admittedConnector struct {
	Name           string            `json:"name"`
	BinarySHA256   string            `json:"binarySha256"`
	BaseURL        string            `json:"baseUrl"`
	TokenPath      string            `json:"tokenPath"`
	CAPath         *string           `json:"caPath"`
	Writes         bool              `json:"writes"`
	Classification string            `json:"classification"`
	Notice         *string           `json:"notice,omitempty"` // optional; never a marking
	Flags          map[string]string `json:"flags"`
	Permissions    map[string]string `json:"permissions"`
}

type profileAdmissionV3 struct {
	SchemaVersion  int      `json:"schemaVersion"`
	Admitted       bool     `json:"admitted"`
	Scope          string   `json:"scope"`
	EnvelopeSHA256 string   `json:"envelopeSha256"`
	PayloadSHA256  string   `json:"payloadSha256"`
	SignerKeyIDs   []string `json:"signerKeyIds"`
	TrustSHA256    string   `json:"trustSha256"`
	NativeSHA256   string   `json:"nativeSha256"`
	Profile        struct {
		ProfileID    string `json:"profileId"`
		TenantID     string `json:"tenantId"`
		DeploymentID string `json:"deploymentId"`
		Sequence     uint64 `json:"sequence"`
		NotBefore    string `json:"notBefore"`
		ExpiresAt    string `json:"expiresAt"`
		Gateway      struct {
			Classification string `json:"classification"`
		} `json:"gateway"`
		Connectors []admittedConnector `json:"connectors"`
	} `json:"profile"`
}

// decodeProfileV3 reads the exact v3 admission output and returns its v1 view, the gateway's
// accredited marking, and the join of the admitted connectors' markings (the most a worker could
// have read). Every marking must parse as a configured banner.
func decodeProfileV3(raw []byte) (profileAdmission, marking.Marking, []marking.Marking, error) {
	var v3 profileAdmissionV3
	var result profileAdmission
	var none marking.Marking
	if err := strictTyped(raw, &v3, map[string]bool{"profile.connectors.caPath": true}); err != nil {
		return result, none, nil, err
	}
	accredited, err := marking.Parse(v3.Profile.Gateway.Classification)
	if v3.SchemaVersion != 3 || v3.Profile.Connectors == nil || err != nil {
		return result, none, nil, errors.New("profile v3 admission refused")
	}
	// Each connector's marking, checked one by one against the accreditation: a join can mark
	// higher than either side on purpose (disjoint REL TO lists become no foreign release), so it
	// would refuse connectors the gateway dominates individually.
	connectors := make([]marking.Marking, 0, len(v3.Profile.Connectors))
	for _, connector := range v3.Profile.Connectors {
		m, err := marking.Parse(connector.Classification)
		if err != nil {
			return result, none, nil, errors.New("profile v3 admission refused")
		}
		connectors = append(connectors, m)
	}
	result.SchemaVersion, result.Admitted, result.Scope = v3.SchemaVersion, v3.Admitted, v3.Scope
	result.EnvelopeSHA256, result.PayloadSHA256 = v3.EnvelopeSHA256, v3.PayloadSHA256
	result.SignerKeyIDs, result.TrustSHA256, result.NativeSHA256 = v3.SignerKeyIDs, v3.TrustSHA256, v3.NativeSHA256
	result.Profile.ProfileID, result.Profile.TenantID = v3.Profile.ProfileID, v3.Profile.TenantID
	result.Profile.DeploymentID, result.Profile.Sequence = v3.Profile.DeploymentID, v3.Profile.Sequence
	result.Profile.NotBefore, result.Profile.ExpiresAt = v3.Profile.NotBefore, v3.Profile.ExpiresAt
	return result, accredited, connectors, nil
}
