package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/matt-deboer/assert-aws-iam-permissions/pkg/types"
	log "github.com/sirupsen/logrus"
)

func parseInput(stdin io.Reader) *types.Inputs {
	data, err := ioutil.ReadAll(stdin)
	if err != nil {
		log.Fatalf("Error reading input from stdin; %v", err)
	}
	var inputs types.Inputs
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		// tabs and newlines are not important to policy documents, and can cause unmarshalling errors
		sanitizedInputs := strings.Replace(string(data), "\n", "", -1)
		sanitizedInputs = strings.Replace(sanitizedInputs, "\t", "", -1)
		data = []byte(sanitizedInputs)

		// try the pieces individually, in case each of the parameters is a separate (quoted) JSON document
		inputsMap := make(map[string]string)
		err2 := json.Unmarshal(data, &inputsMap)
		if err2 != nil {
			log.Fatalf("Error unmarshaling inputs json; %v", err2)
		}
		if policyJSON, ok := inputsMap["policy_json"]; ok {
			inputs.PolicyJSON = policyJSON
		}

		if assertions, ok := inputsMap["assertions"]; ok {
			err := json.Unmarshal([]byte(assertions), &inputs.Assertions)
			if err != nil {
				log.Fatalf("Error unmarshaling inputs.assertions; %v", err)
			}
		}
	}
	return &inputs
}

func serializeOutput(policyJSON string, stdout io.Writer) error {
	_, err := stdout.Write([]byte(fmt.Sprintf(`{"policy_json": %s}`, strconv.Quote(policyJSON))))
	return err
}
