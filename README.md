assert-aws-iam-permissions
===

[![Build Status](https://travis-ci.org/matt-deboer/assert-aws-iam-permissions.svg?branch=master)](https://travis-ci.org/matt-deboer/assert-aws-iam-permissions)
[![Docker Pulls](https://img.shields.io/docker/pulls/mattdeboer/assert-aws-iam-permissions.svg)](https://hub.docker.com/r/mattdeboer/assert-aws-iam-permissions/)

**assert-aws-iam-permissions** is a command-line utility for evaluation of AWS IAM policy documents against a set of asserted permissions (using the AWS Policy Simulation API).

Motivation
---

It was created specifically for use as an External Data Source in Terraform--used to assure that the expected permissions were actually enforced by a given policy before creating that policy.

Usage
---

```
NAME:
   assert-aws-iam-permissions

USAGE:
   assert-aws-iam-permissions [global options] command [command options] [arguments...]

VERSION:
   v0.1

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --policy-json value  The full contents of the IAM policy document; if empty,
                            assertions are read from JSON on stdin (under the key "policy_json") [$AAIP_POLICY_JSON]
   --assertions value   A JSON array of assertion statement objects, with the following structure:
                              "expected_result":          "allowed|implicitDeny|explicitDeny|deny|denied" // 'deny' or 'denied' can be used to catch any deny type result
                              "action_names":             ["service:Action"...],
                              "resource_arns":            ["arn:aws:..."],
                              "resource_policy":          "policy",
                              "resource_owner":           "owner",
                              "caller_arn":               "caller",
                              "context_entries"": {
                                "key": ["values"],
                                ...
                              },
                              "resource_handling_option": "option"
                              if empty, assertions are read from JSON on stdin (under the key "assertions") [$AAIP_ASSERTIONS]
   --read-stdin, -i     whether to read inputs from stdin [$AAIP_READ_STDIN]
   --verbose, -V        Log debugging information [$AAIP_VERBOSE]
   --help, -h           show help
   --version, -v        print the version
```