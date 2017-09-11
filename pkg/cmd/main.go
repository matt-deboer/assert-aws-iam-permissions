package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/policy"
	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/types"
	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/version"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	run(os.Args, os.Stdin, os.Stdout)
}

func argError(c *cli.Context, msg string, args ...interface{}) {
	log.Errorf(msg+"\n", args...)
	cli.ShowAppHelp(c)
	os.Exit(1)
}

func run(args []string, stdin io.Reader, stdout io.Writer) {
	app := cli.NewApp()
	app.Name = version.Name
	app.Version = version.Version
	app.Usage = ``
	prefix := "AAIP_"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "policy-json",
			Usage: `The full contents of the IAM policy document; if empty,
			assertions are read from JSON on stdin (under the key "policy_json")`,
			EnvVar: prefix + "POLICY_JSON",
		},
		cli.StringFlag{
			Name: "assertions",
			Usage: `A JSON array of assertion statement objects, with the following structure:
				"comment":                  "This statement should be true",
			  "expected_result":          "allowed|implicitDeny|explicitDeny|deny|denied" // 'deny' or 'denied' can be used to catch any deny type result
				"action_names":             ["service:Action"...],
				"resource_arns":            ["arn:aws:..."],
				"resource_policy":          "policy",
				"resource_owner":           "owner",
				"caller_arn":               "caller",
				"context_entries"": {
					"key": {"type": "the_type","values": ["some_values"...]},
					...
				},
				"resource_handling_option": "option"
				if empty, assertions are read from JSON on stdin (under the key "assertions")`,
			EnvVar: prefix + "ASSERTIONS",
		},
		cli.BoolFlag{
			Name:   "read-stdin, i",
			Usage:  "whether to read inputs from stdin",
			EnvVar: prefix + "READ_STDIN",
		},
		cli.BoolFlag{
			Name:   "verbose, V",
			Usage:  "Log debugging information",
			EnvVar: prefix + "VERBOSE",
		},
	}
	app.Action = func(c *cli.Context) {

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		var inputs types.Inputs
		policyJSONString := c.String("policy-json")
		assertionsString := c.String("assertions")

		if len(policyJSONString) > 0 {
			inputs.PolicyJSON = policyJSONString
		}
		if len(assertionsString) > 0 {
			err := json.Unmarshal([]byte(assertionsString), inputs.Assertions)
			if err != nil {
				log.Fatalf("Failed to unmarshal assertions array; %v", err)
			}
		}
		if c.Bool("read-stdin") {
			stdinInputs := parseInput(stdin)
			if len(stdinInputs.Assertions) > 0 {
				inputs.Assertions = stdinInputs.Assertions
			}
			if len(stdinInputs.PolicyJSON) > 0 {
				inputs.PolicyJSON = stdinInputs.PolicyJSON
			}
		}
		if len(inputs.Assertions) == 0 {
			argError(c, "'assertions' is required")
		}
		if len(inputs.PolicyJSON) == 0 {
			argError(c, "'policy-json' is required")
		}
		_, err := policy.AssertPermissions(inputs.Assertions, inputs.PolicyJSON)
		if err != nil {
			log.Fatal(err)
		}
		serializeOutput(inputs.PolicyJSON, stdout)
	}
	app.Run(args)
}
