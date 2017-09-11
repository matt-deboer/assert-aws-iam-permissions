package policy

import (
	"testing"

	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/types"
)

const testPolicy = `
{
	"Version": "2012-10-17",
	"Statement": [
			{
					"Sid": "",
					"Effect": "Allow",
					"Action": [
							"sts:GetCallerIdentity",
							"route53:List*",
							"route53:Get*",
							"route53:ChangeResourceRecordSets",
							"ec2:DescribeImages",
							"ec2:DescribeAccountAttributes"
					],
					"Resource": "*"
			},
			{
					"Sid": "",
					"Effect": "Allow",
					"Action": [
							"s3:PutObject",
							"s3:GetObject",
							"s3:DeleteObject"
					],
					"Resource": [
							"arn:aws:s3:::my-bucket/bucket-path/*",
							"arn:aws:s3:::my-bucket/bucket-path"
					]
			},
			{
					"Sid": "",
					"Effect": "Allow",
					"Action": "s3:ListBucket",
					"Resource": "arn:aws:s3:::my-bucket"
			},
			{
					"Sid": "",
					"Effect": "Allow",
					"Action": "s3:ListAllMyBuckets",
					"Resource": "*"
			}
	]
}
`

func TestAssertBasicPermissions(t *testing.T) {

	assertions := []*types.Assertion{
		&types.Assertion{
			ActionNames:    []string{"s3:ListBucket"},
			ResourceArns:   []string{"arn:aws:s3:::my-bucket"},
			ExpectedResult: "allowed",
		},
	}

	valid, err := AssertPermissions(assertions, testPolicy)
	if !valid {
		t.Error(err)
	}
}

func TestAssertWildcardPermissions(t *testing.T) {

	assertions := []*types.Assertion{
		&types.Assertion{
			ActionNames:    []string{"ec2:AssociateIamInstanceProfile"},
			ResourceArns:   []string{"arn:aws:s3:::my-bucket/some-other-path"},
			ExpectedResult: "implicitDeny",
		},
	}

	valid, err := AssertPermissions(assertions, testPolicy)
	if !valid {
		t.Error(err)
	}
}

const testPolicyWithContext = `
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "",
			"Effect": "Allow",
			"Action": [
				"ec2:AssociateIamInstanceProfile",
				"ec2:DescribeIamInstanceProfileAssociation",
				"ec2:DisassociateIamInstanceProfile",
				"ec2:ReplaceIamInstanceProfileAssociation"
			],
			"Resource": [ 
				"arn:aws:ec2::123456789012:*" 
			],
			"Condition": {
				"ForAllValues:StringLike": {
						"ec2:InstanceProfile": "arn:aws:iam::123456789012:instance-profile/example/*",
						"ec2:ResourceTag/application-group": "example"
				},
				"ForAllValues:StringNotLike": {
						"ec2:InstanceProfile": "arn:aws:iam::123456789012:instance-profile/example/special-role/*"
				}
			}
		}
	]
}
`

func TestAssertWithContextEntries(t *testing.T) {
	assertions := []*types.Assertion{
		&types.Assertion{
			ActionNames:    []string{"ec2:AssociateIamInstanceProfile"},
			ResourceArns:   []string{"arn:aws:ec2::123456789012:instance/*"},
			ExpectedResult: "denied",
			ContextEntries: map[string]*types.ContextEntryValue{
				"ec2:ResourceTag/application-group": &types.ContextEntryValue{Type: "string", Values: []string{"not-example"}},
			},
		},
		&types.Assertion{
			ActionNames:    []string{"ec2:AssociateIamInstanceProfile"},
			ResourceArns:   []string{"arn:aws:ec2::123456789012:instance/*"},
			ExpectedResult: "denied",
			ContextEntries: map[string]*types.ContextEntryValue{
				"ec2:ResourceTag/application-group": &types.ContextEntryValue{Type: "string", Values: []string{"example"}},
				"ec2:InstanceProfile":               &types.ContextEntryValue{Type: "string", Values: []string{"arn:aws:iam::123456789012:instance-profile/example/special-role/045988a5975b2dfdf"}},
			},
		},
		&types.Assertion{
			ActionNames:    []string{"ec2:AssociateIamInstanceProfile"},
			ResourceArns:   []string{"arn:aws:ec2::123456789012:instance/*"},
			ExpectedResult: "allowed",
			ContextEntries: map[string]*types.ContextEntryValue{
				"ec2:ResourceTag/application-group": &types.ContextEntryValue{Type: "string", Values: []string{"example"}},
				"ec2:InstanceProfile":               &types.ContextEntryValue{Type: "string", Values: []string{"arn:aws:iam::123456789012:instance-profile/example/other-role/346788a5975b4gacd"}},
			},
		},
	}

	valid, err := AssertPermissions(assertions, testPolicyWithContext)
	if !valid {
		t.Error(err)
	}

}
