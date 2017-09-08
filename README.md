assert-aws-iam-permissions
===

[![Build Status](https://travis-ci.org/matt-deboer/assert-aws-iam-permissions.svg?branch=master)](https://travis-ci.org/matt-deboer/assert-aws-iam-permissions)
[![Docker Pulls](https://img.shields.io/docker/pulls/mattdeboer/assert-aws-iam-permissions.svg)](https://hub.docker.com/r/mattdeboer/assert-aws-iam-permissions/)
[![Coverage Status](https://coveralls.io/repos/github/matt-deboer/assert-aws-iam-permissions/badge.svg?branch=master)](https://coveralls.io/github/matt-deboer/assert-aws-iam-permissions?branch=master) 
[![Go Report Card](https://goreportcard.com/badge/github.com/matt-deboer/assert-aws-iam-permissions)](https://goreportcard.com/report/github.com/matt-deboer/assert-aws-iam-permissions)

**assert-aws-iam-permissions** is a command-line utility for evaluation of AWS IAM policy documents against a set of asserted permissions (using the AWS Policy Simulation API).

Motivation
---

It was created specifically for use as an External Data Source in Terraform--used to assure that the expected permissions were actually enforced by a given policy before creating that policy.
