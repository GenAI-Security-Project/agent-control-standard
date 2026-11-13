package envelope

import "testing"

func TestValidateJSONRPCRequestRejectsNonScalarIdentifiers(t *testing.T) {
	for name, id := range map[string]string{
		"boolean": "true",
		"object":  `{}`,
		"array":   `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			in, err := Parse([]byte(`{"jsonrpc":"2.0","method":"steps/toolCallRequest","id":` + id + `,"params":{}}`))
			if err != nil {
				t.Fatal(err)
			}
			if err := in.ValidateJSONRPCRequest(); err == nil {
				t.Fatalf("accepted JSON-RPC id %s", id)
			}
		})
	}
}
