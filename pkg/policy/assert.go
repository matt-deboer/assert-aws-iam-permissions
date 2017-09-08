package policy

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/types"
)

// AssertPermissions evaluates the provided set of assertions against the
// provided policy document
func AssertPermissions(assertions []*types.Assertion, policyJSON string) (valid bool, err error) {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create a IAM service client.
	iamSvc := iam.New(sess)

	errors := 0
	messages := []string{}

	for _, assertion := range assertions {

		contextEntries := []*iam.ContextEntry{}
		for k, v := range assertion.ContextEntries {
			contextEntries = append(contextEntries, &iam.ContextEntry{
				ContextKeyName:   aws.String(k),
				ContextKeyValues: aws.StringSlice(v),
			})
		}

		resp, err := iamSvc.SimulateCustomPolicy(&iam.SimulateCustomPolicyInput{
			ActionNames:     aws.StringSlice(assertion.ActionNames),
			CallerArn:       aws.String(assertion.CallerArn),
			PolicyInputList: aws.StringSlice([]string{policyJSON}),
			ResourceOwner:   aws.String(assertion.ResourceOwner),
			ResourcePolicy:  aws.String(assertion.ResourcePolicy),
			ContextEntries:  contextEntries,
		})

		if err != nil {
			return false, err
		}

		for _, result := range resp.EvaluationResults {
			if assertion.ExpectedResult != aws.StringValue(result.EvalDecision) {
				errors++
				messages = append(messages, fmt.Sprintf("Expected '%s', but got '%s' for assertion %v",
					assertion.ExpectedResult, aws.StringValue(result.EvalDecision), assertion))
			}
		}
	}

	if errors > 0 {
		return false, fmt.Errorf(strings.Join(messages, ","))
	}
	return true, nil
}
