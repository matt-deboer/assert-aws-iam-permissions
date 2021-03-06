package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/types"
)

// AssertPermissions evaluates the provided set of assertions against the
// provided policy document
func AssertPermissions(assertions []*types.Assertion, policyJSON string, assumeRoleARN string) error {

	iamSvc := initIAM(assumeRoleARN)

	errors := 0
	messages := []string{}

	for _, assertion := range assertions {

		contextEntries := []*iam.ContextEntry{}
		for k, v := range assertion.ContextEntries {
			contextKeyType := "string"
			if len(v.Type) > 0 {
				contextKeyType = v.Type
			}
			contextEntries = append(contextEntries, &iam.ContextEntry{
				ContextKeyName:   aws.String(k),
				ContextKeyValues: aws.StringSlice(v.Values),
				ContextKeyType:   aws.String(contextKeyType),
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
			return err
		}

		for _, result := range resp.EvaluationResults {
			evalDecision := aws.StringValue(result.EvalDecision)
			unexpectedResult := assertion.ExpectedResult != evalDecision
			if assertion.ExpectedResult == "deny" || assertion.ExpectedResult == "denied" {
				unexpectedResult = !strings.HasSuffix(evalDecision, "Deny")
			}

			if unexpectedResult {
				errors++
				msg := fmt.Sprintf("[POLICY ASSERTION FAILED] %s ( for %s [ %s ]: expected '%s', but got '%s' )",
					assertion.Comment, aws.StringValue(result.EvalActionName),
					aws.StringValue(result.EvalResourceName), assertion.ExpectedResult,
					aws.StringValue(result.EvalDecision))
				messages = append(messages, msg)
			}
		}
	}

	if errors > 0 {
		return fmt.Errorf(strings.Join(messages, ","))
	}
	return nil
}

func convertStringArg(arg string) *string {
	var argRef *string
	if len(arg) > 0 {
		argRef = aws.String(arg)
	}
	return argRef
}

// AssertPolicyLength evaluates the length of the policy document (excluding whitespace) against
// the expected maximum length
func AssertPolicyLength(maxLength int, policyJSON string) error {
	length := len(regexp.MustCompile(`\s+`).ReplaceAllString(policyJSON, ""))
	if length > maxLength {
		return fmt.Errorf("Policy document is %d characters over the expected limit of %d", (length - maxLength), maxLength)
	}
	return nil
}

func initIAM(assumeRoleARN string) *iam.IAM {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	var iamSvc *iam.IAM
	if len(assumeRoleARN) > 0 {
		creds := stscreds.NewCredentials(sess, assumeRoleARN)
		iamSvc = iam.New(sess, &aws.Config{Credentials: creds})
	} else {
		iamSvc = iam.New(sess)
	}
	return iamSvc
}
