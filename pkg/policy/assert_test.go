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
			ActionNames:    []string{"s3:GetObject"},
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
			ActionNames:    []string{"s3:ListBucket"},
			ResourceArns:   []string{"arn:aws:s3:::my-bucket/some-other-path"},
			ExpectedResult: "implicitDeny",
		},
	}

	valid, err := AssertPermissions(assertions, testPolicy)
	if !valid {
		t.Error(err)
	}
}
