package types

type Assertion struct {
	ExpectedResult         string              `json:"expected_result"`
	ActionNames            []string            `json:"action_names"`
	ResourceArns           []string            `json:"resource_arns"`
	ResourcePolicy         string              `json:"resource_policy"`
	ResourceOwner          string              `json:"resource_owner"`
	CallerArn              string              `json:"caller_arn"`
	ContextEntries         map[string][]string `json:"context_entries"`
	ResourceHandlingOption string              `json:"resource_handling_option"`
}

type Inputs struct {
	Assertions []*Assertion `json:"assertions"`
	PolicyJSON string       `json:"policy_json"`
}
