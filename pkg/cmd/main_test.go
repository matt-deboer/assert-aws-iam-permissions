package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
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
const quotedTestPolicy = `
{
	\"Version\": \"2012-10-17\",
	\"Statement\": [
			{
					\"Sid\": \"\",
					\"Effect\": \"Allow\",
					\"Action\": [
							\"sts:GetCallerIdentity\",
							\"route53:List*\",
							\"route53:Get*\",
							\"route53:ChangeResourceRecordSets\",
							\"ec2:DescribeImages\",
							\"ec2:DescribeAccountAttributes\"
					],
					\"Resource\": \"*\"
			},
			{
					\"Sid\": \"\",
					\"Effect\": \"Allow\",
					\"Action\": [
							\"s3:PutObject\",
							\"s3:GetObject\",
							\"s3:DeleteObject\"
					],
					\"Resource\": [
							\"arn:aws:s3:::my-bucket/bucket-path/*\",
							\"arn:aws:s3:::my-bucket/bucket-path\"
					]
			},
			{
					\"Sid\": \"\",
					\"Effect\": \"Allow\",
					\"Action\": \"s3:ListBucket\",
					\"Resource\": \"arn:aws:s3:::my-bucket\"
			},
			{
					\"Sid\": \"\",
					\"Effect\": \"Allow\",
					\"Action\": \"s3:ListAllMyBuckets\",
					\"Resource\": \"*\"
			}
	]
}
`

func TestAssertBasicPermissions(t *testing.T) {

	args := []string{"assert-aws-iam-permissions", "--read-stdin"}
	outputs := &bytes.Buffer{}
	inputs := bytes.NewBufferString(fmt.Sprintf(`
	{
		"assertions": [
			{
				"action_names":  ["s3:ListBucket"],
				"resource_arns": ["arn:aws:s3:::my-bucket"],
				"expected_result": "allowed"
			}
		],
		"max_length": 1024,
		"policy_json": %s
	}
	`, strconv.Quote(testPolicy)))

	run(args, inputs, outputs)
}

func TestAssertBasicPermissions_QuotedPolicy(t *testing.T) {

	args := []string{"assert-aws-iam-permissions", "--read-stdin"}
	outputs := &bytes.Buffer{}
	inputs := bytes.NewBufferString(fmt.Sprintf(`
		{
			"assertions": "[
				{
					\"action_names\":  [\"s3:ListBucket\"],
					\"resource_arns\": [\"arn:aws:s3:::my-bucket\"],
					\"expected_result\": \"allowed\"
				}
			]",
			"max_length": 5120,
			"policy_json": "%s"
		}
		`, quotedTestPolicy))

	run(args, inputs, outputs)
}

const terraformQuotedInputs = `
{
"assertions": "[
	{
		\"action_names\":  [\"s3:ListBucket\"],
		\"resource_arns\": [\"arn:aws:s3:::my-bucket\"],
		\"expected_result\": \"allowed\"
	}
]",
"max_length": %d,
"policy_json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"acm:Resend*\",\n        \"acm:Request*\",\n        \"acm:List*\",\n        \"acm:Get*\",\n        \"acm:Describe*\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"autoscaling:UpdateAutoScalingGroup\",\n        \"autoscaling:TerminateInstanceInAutoScalingGroup\",\n        \"autoscaling:SetInstanceProtection\",\n        \"autoscaling:SetDesiredCapacity\",\n        \"autoscaling:Describe*\",\n        \"autoscaling:DeleteLaunchConfiguration\",\n        \"autoscaling:DeleteAutoScalingGroup\",\n        \"autoscaling:CreateLaunchConfiguration\",\n        \"autoscaling:CreateAutoScalingGroup\",\n        \"autoscaling:AttachLoadBalancers\",\n        \"autoscaling:AttachLoadBalancerTargetGroups\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"ForAllValues:StringLike\": {\n          \"autoscaling:ResourceTag/application-group\": \"important-stuff\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"ec2:UnmonitorInstances\",\n        \"ec2:TerminateInstances\",\n        \"ec2:StopInstances\",\n        \"ec2:StartInstances\",\n        \"ec2:RunScheduledInstances\",\n        \"ec2:RunInstances\",\n        \"ec2:ResetSnapshotAttribute\",\n        \"ec2:ResetNetworkInterfaceAttribute\",\n        \"ec2:ResetInstanceAttribute\",\n        \"ec2:ResetImageAttribute\",\n        \"ec2:RequestSpotInstances\",\n        \"ec2:RequestSpotFleet\",\n        \"ec2:ReportInstanceStatus\",\n        \"ec2:ReleaseHosts\",\n        \"ec2:ReleaseAddress\",\n        \"ec2:RegisterImage\",\n        \"ec2:RebootInstances\",\n        \"ec2:MonitorInstances\",\n        \"ec2:ModifyVolumeAttribute\",\n        \"ec2:ModifyVolume\",\n        \"ec2:ModifySubnetAttribute\",\n        \"ec2:ModifySpotFleetRequest\",\n        \"ec2:ModifySnapshotAttribute\",\n        \"ec2:ModifyNetworkInterfaceAttribute\",\n        \"ec2:ModifyInstancePlacement\",\n        \"ec2:ModifyInstanceAttribute\",\n        \"ec2:ModifyImageAttribute\",\n        \"ec2:ModifyIdentityIdFormat\",\n        \"ec2:ModifyIdFormat\",\n        \"ec2:ModifyHosts\",\n        \"ec2:ImportVolume\",\n        \"ec2:ImportSnapshot\",\n        \"ec2:ImportKeyPair\",\n        \"ec2:ImportInstance\",\n        \"ec2:ImportImage\",\n        \"ec2:GetReservedInstancesExchangeQuote\",\n        \"ec2:GetPasswordData\",\n        \"ec2:GetHostReservationPurchasePreview\",\n        \"ec2:GetConsoleScreenshot\",\n        \"ec2:GetConsoleOutput\",\n        \"ec2:EnableVolumeIO\",\n        \"ec2:DisassociateAddress\",\n        \"ec2:DetachVolume\",\n        \"ec2:DetachNetworkInterface\",\n        \"ec2:Describe*\",\n        \"ec2:DeregisterImage\",\n        \"ec2:DeleteVolume\",\n        \"ec2:DeleteSnapshot\",\n        \"ec2:DeletePlacementGroup\",\n        \"ec2:DeleteKeyPair\",\n        \"ec2:DeleteFlowLogs\",\n        \"ec2:CreateVolume\",\n        \"ec2:CreateTags\",\n        \"ec2:CreateSnapshot\",\n        \"ec2:CreatePlacementGroup\",\n        \"ec2:CreateKeyPair\",\n        \"ec2:CreateInstanceExportTask\",\n        \"ec2:CreateImage\",\n        \"ec2:CreateFpgaImage\",\n        \"ec2:CreateFlowLogs\",\n        \"ec2:CopySnapshot\",\n        \"ec2:CopyImage\",\n        \"ec2:CancelSpotInstanceRequests\",\n        \"ec2:CancelSpotFleetRequests\",\n        \"ec2:CancelImportTask\",\n        \"ec2:CancelExportTask\",\n        \"ec2:CancelConversionTask\",\n        \"ec2:CancelBundleTask\",\n        \"ec2:BundleInstance\",\n        \"ec2:AttachVolume\",\n        \"ec2:AttachNetworkInterface\",\n        \"ec2:AssociateAddress\",\n        \"ec2:AssignPrivateIpAddresses\",\n        \"ec2:AllocateHosts\",\n        \"ec2:AllocateAddress\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"ForAllValues:StringLike\": {\n          \"aws:RequestTag/application-group\": \"important-stuff\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"ec2:ReplaceIamInstanceProfileAssociation\",\n        \"ec2:DisassociateIamInstanceProfile\",\n        \"ec2:DescribeIamInstanceProfileAssociation\",\n        \"ec2:AssociateIamInstanceProfile\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"ForAllValues:StringLike\": {\n          \"ec2:InstanceProfile\": \"arn:aws:iam::1234567891012:instance-profile/important-stuff/*\",\n          \"ec2:ResourceTag/application-group\": \"important-stuff\"\n        },\n        \"ForAllValues:StringNotLike\": {\n          \"ec2:InstanceProfile\": \"arn:aws:iam::*:instance-profile/important-stuff/application-deployer-assumer/*\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"elasticloadbalancing:SetSubnets\",\n        \"elasticloadbalancing:SetSecurityGroups\",\n        \"elasticloadbalancing:SetRulePriorities\",\n        \"elasticloadbalancing:SetLoadBalancerPoliciesOfListener\",\n        \"elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer\",\n        \"elasticloadbalancing:SetLoadBalancerListenerSSLCertificate\",\n        \"elasticloadbalancing:RemoveTags\",\n        \"elasticloadbalancing:RegisterTargets\",\n        \"elasticloadbalancing:RegisterInstancesWithLoadBalancer\",\n        \"elasticloadbalancing:ModifyTargetGroupAttributes\",\n        \"elasticloadbalancing:ModifyTargetGroup\",\n        \"elasticloadbalancing:ModifyRule\",\n        \"elasticloadbalancing:ModifyLoadBalancerAttributes\",\n        \"elasticloadbalancing:ModifyListener\",\n        \"elasticloadbalancing:EnableAvailabilityZonesForLoadBalancer\",\n        \"elasticloadbalancing:DisableAvailabilityZonesForLoadBalancer\",\n        \"elasticloadbalancing:DetachLoadBalancerFromSubnets\",\n        \"elasticloadbalancing:DescribeTargetHealth\",\n        \"elasticloadbalancing:DescribeTargetGroups\",\n        \"elasticloadbalancing:DescribeTargetGroupAttributes\",\n        \"elasticloadbalancing:DescribeTags\",\n        \"elasticloadbalancing:DescribeSSLPolicies\",\n        \"elasticloadbalancing:DescribeRules\",\n        \"elasticloadbalancing:DescribeLoadBalancers\",\n        \"elasticloadbalancing:DescribeLoadBalancerPolicyTypes\",\n        \"elasticloadbalancing:DescribeLoadBalancerPolicies\",\n        \"elasticloadbalancing:DescribeLoadBalancerAttributes\",\n        \"elasticloadbalancing:DescribeListeners\",\n        \"elasticloadbalancing:DescribeInstanceHealth\",\n        \"elasticloadbalancing:DeregisterTargets\",\n        \"elasticloadbalancing:DeregisterInstancesFromLoadBalancer\",\n        \"elasticloadbalancing:DeleteTargetGroup\",\n        \"elasticloadbalancing:DeleteRule\",\n        \"elasticloadbalancing:DeleteLoadBalancerPolicy\",\n        \"elasticloadbalancing:DeleteLoadBalancerListeners\",\n        \"elasticloadbalancing:DeleteLoadBalancer\",\n        \"elasticloadbalancing:DeleteListener\",\n        \"elasticloadbalancing:CreateTargetGroup\",\n        \"elasticloadbalancing:CreateRule\",\n        \"elasticloadbalancing:CreateLoadBalancerPolicy\",\n        \"elasticloadbalancing:CreateLoadBalancerListeners\",\n        \"elasticloadbalancing:CreateLoadBalancer\",\n        \"elasticloadbalancing:CreateListener\",\n        \"elasticloadbalancing:CreateLBCookieStickinessPolicy\",\n        \"elasticloadbalancing:CreateAppCookieStickinessPolicy\",\n        \"elasticloadbalancing:ConfigureHealthCheck\",\n        \"elasticloadbalancing:AttachLoadBalancerToSubnets\",\n        \"elasticloadbalancing:ApplySecurityGroupsToLoadBalancer\",\n        \"elasticloadbalancing:AddTags\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"ForAllValues:StringLike\": {\n          \"aws:RequestTag/application-group\": \"important-stuff\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"iam:ListRoles\",\n        \"iam:ListRolePolicies\",\n        \"iam:ListPoliciesGrantingServiceAccess\",\n        \"iam:ListPolicies\",\n        \"iam:ListInstanceProfilesForRole\",\n        \"iam:ListInstanceProfiles\",\n        \"iam:ListEntitiesForPolicy\",\n        \"iam:ListAttachedRolePolicies\",\n        \"iam:GetRolePolicy\",\n        \"iam:GetRole\",\n        \"iam:GetPolicy\",\n        \"iam:GetInstanceProfile\"\n      ],\n      \"Resource\": [\n        \"arn:aws:iam::*:role/important-stuff/*\",\n        \"arn:aws:iam::*:policy/important-stuff/*\",\n        \"arn:aws:iam::*:instance-profile/important-stuff/*\"\n      ]\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:PassRole\",\n      \"Resource\": \"arn:aws:iam::1234567891012:role/important-stuff/*\",\n      \"Condition\": {\n        \"ForAllValues:StringNotLike\": {\n          \"iam:RoleArn\": \"arn:aws:iam::1234567891012:role/important-stuff/application-deployer-assumer/important-stuff-application-deployer-assumer\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"sts:GetCallerIdentity\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"route53:List*\",\n        \"route53:Get*\",\n        \"route53:ChangeResourceRecordSets\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"s3:PutObject\",\n        \"s3:GetObject\",\n        \"s3:DeleteObject\"\n      ],\n      \"Resource\": [\n        \"arn:aws:s3:::my-bucket/important-stuff/*\",\n        \"arn:aws:s3:::my-bucket/important-stuff\"\n      ]\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"s3:ListBucket\",\n      \"Resource\": \"arn:aws:s3:::my-bucket\"\n    },\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": \"s3:ListAllMyBuckets\",\n      \"Resource\": \"*\"\n    }\n  ]\n}"
}
`

func TestAssertBasicPermissions_TerraformQuotedPolicy(t *testing.T) {

	args := []string{"assert-aws-iam-permissions", "--read-stdin"}
	outputs := &bytes.Buffer{}
	inputs := bytes.NewBufferString(fmt.Sprintf(terraformQuotedInputs, 10240))

	run(args, inputs, outputs)
}

func TestAssertBasicPermissions_TerraformQuotedPolicyMaxLengthFailure(t *testing.T) {

	if os.Getenv("SHOULD_EXIT") == "1" {
		// this is the actual test, which should cause exit because of policy length exceeded
		args := []string{"assert-aws-iam-permissions", "--read-stdin"}
		outputs := &bytes.Buffer{}
		inputs := bytes.NewBufferString(fmt.Sprintf(terraformQuotedInputs, 5120))

		run(args, inputs, outputs)
	} else {
		cmd := exec.Command(os.Args[0], "-test.run=TestAssertBasicPermissions_TerraformQuotedPolicyMaxLengthFailure")
		cmd.Env = append(os.Environ(), "SHOULD_EXIT=1")
		err := cmd.Run()
		if e, ok := err.(*exec.ExitError); ok && !e.Success() {
			return
		}
		t.Fatalf("process ran with err %v, want exit status 1", err)
	}
}
