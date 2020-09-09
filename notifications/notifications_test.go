package notifications

import (
	"testing"

	"go.mozilla.org/person-api"

	"github.com/stretchr/testify/assert"
)

func TestEncryptMailBody(t *testing.T) {
	origBody := []byte("test message")
	person := &person_api.Person{
		PGPPublicKeys: person_api.StandardAttributeValues{
			Values: map[string]interface{}{
				"key_one": "0xF69E4901EDBAD2D1753F8C67A64535C4163FB307",
			},
		},
	}

	out, err := EncryptMailBody(origBody, person)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}
