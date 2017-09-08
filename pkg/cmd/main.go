package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/types"
	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/version"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	run(os.Args, os.Stdin)
}

func argError(c *cli.Context, msg string, args ...interface{}) {
	log.Errorf(msg+"\n", args...)
	cli.ShowAppHelp(c)
	os.Exit(1)
}

func run(args []string, stdin *os.File) {
	app := cli.NewApp()
	app.Name = version.Name
	app.Version = version.Version
	app.Usage = ``
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "policy-json",
			Usage: `The full contents of the IAM policy document; if empty,
			assertions are read from JSON on stdin (under the key "policy_json")`,
			EnvVar: "POLICY_JSON",
		},
		cli.StringFlag{
			Name: "assertions",
			Usage: `A JSON array of assertion statement objects, with the following structure:
				"expected_result": "allowed|denied"
				"action_names": 		["service:Action"...],
				"resource_arns":	 	["arn:aws:..."],
				"resource_policy": 	"policy",
				"resource_owner": 	"owner",
				"caller_arn": "caller",
				"context_entries"": {
					"key": ["values"],
					...
				},
				"resource_handling_option": "option"
				if empty, assertions are read from JSON on stdin (under the key "assertions")`,
			EnvVar: "ASSERTIONS",
		},

		cli.BoolFlag{
			Name:   "verbose, V",
			Usage:  "Log debugging information",
			EnvVar: "assert-aws-iam-permissions_VERBOSE",
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
		if len(policyJSONString) == 0 || len(assertionsString) == 0 {
			stdinInputs := parseInput(stdin)
			if len(stdinInputs.Assertions) > 0 {
				inputs.Assertions = stdinInputs.Assertions
			}
			if len(stdinInputs.PolicyJSON) > 0 {
				inputs.PolicyJSON = stdinInputs.PolicyJSON
			}
		}

	}
	app.Run(args)
}

func parseInput(stdin *os.File) *types.Inputs {
	data, err := ioutil.ReadAll(stdin)
	if err != nil {
		log.Fatalf("Error reading input from stdin; %v", err)
	}
	var inputs types.Inputs
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		log.Fatalf("Error unmarshaling inputs json; %v", err)
	}
	return &inputs
}
