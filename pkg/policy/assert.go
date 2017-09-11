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
			ResourceArns:    aws.StringSlice(assertion.ResourceArns),
			CallerArn:       convertStringArg(assertion.CallerArn),
			PolicyInputList: aws.StringSlice([]string{policyJSON}),
			ResourceOwner:   convertStringArg(assertion.ResourceOwner),
			ResourcePolicy:  convertStringArg(assertion.ResourcePolicy),
			ContextEntries:  contextEntries,
		})

		if err != nil {
			return false, err
		}

		for _, result := range resp.EvaluationResults {
			evalDecision := aws.StringValue(result.EvalDecision)
			unexpectedResult := assertion.ExpectedResult != evalDecision
			if assertion.ExpectedResult == "deny" || assertion.ExpectedResult == "denied" {
				unexpectedResult = !strings.HasSuffix(evalDecision, "Deny")
			}

			if unexpectedResult {
				errors++
				msg := fmt.Sprintf("for %s [ %s ]: expected '%s', but got '%s'",
					aws.StringValue(result.EvalActionName), aws.StringValue(result.EvalResourceName), assertion.ExpectedResult, aws.StringValue(result.EvalDecision))
				messages = append(messages, msg)
			}
		}
	}

	if errors > 0 {
		return false, fmt.Errorf(strings.Join(messages, ","))
	}
	return true, nil
}

func convertStringArg(arg string) *string {
	var argRef *string
	if len(arg) > 0 {
		argRef = aws.String(arg)
	}
	return argRef
}
