package notifications

import (
	"testing"

	person_api "go.mozilla.org/person-api"

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

func TestAgeEncryptMailBodyRsa(t *testing.T) {
	origBody := []byte("test message")
	person := &person_api.Person{
		SSHPublicKeys: person_api.StandardAttributeValues{
			Values: map[string]interface{}{
				"key_one": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDOSSQZw8tPFls6SzkyeElSk/MobGPUlvNQsMfMJCzcsHRM1BpCA3DQT3XrcUaO/OoXbYbScqxSCUEaeeFMwCog832Pjypsq/hs9qQbtK2D9lBJzUDiJzxGPMQEJ/QOW533yu+jJd7CTePTen/tKeqyqQdu/8hm92ZiP473ztKiQPLH3gfoT6iia8ZgzlHq/fsbv+O/A6FVOkYDauLOtYpGTI3z/QnL9DnpvT27et5xtKP7Q6ZKOAJnCBbeK1QIqbg+JrTNk5toM/jbssVN/I+fDruSeyvpK2bEmPe4fHJTazK+w8bOOIE8J4aaMfiNpvAoN6HywCY1l+TeE1oolj7RoivwEfFL8VV4sXigG3s8SCLlKvXPT8J5m6eY9DJXSmvKxcIRMIIj695ETlZ/rO0Cy83oLnOViIQbkzO5mlApNWeAMgGD6iSVJcqv5lLW5VkCk3NZxw3kF4eew0Sw0a5UveD5qHH1cWPeete+lX+cW2KkQzCtvW2ns8VzMZtQOROqPjJyikKU2CLeI/VRZB5PKe1liBgYOhUZeotXBe6prdGFoRhL6N+H3kk8K3BQqnJTYxpamT2Wc8ESxdNDMCzqmn47bIx1gKYBKulg4OK6F6kAjdy/lFiqoFuMYValdYVpTtR98jhaYwSY9pCzqaSg4pGtXNMstBxm4dvLW74OaQ== test_fixture_rsa4096",
				"key_two": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1BP2MqjpXMCUUBtdcPefr9RymkT1yV+l9y5S0I2JFc test_fixture_ed25519",
			},
		},
	}

	out, err := AgeEncryptMailBody(origBody, person)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.Contains(t, string(out), "-----BEGIN AGE ENCRYPTED FILE-----")
	assert.Contains(t, string(out), "-----END AGE ENCRYPTED FILE-----")
}

func TestAgeEncryptMailBodyEd25519(t *testing.T) {
	origBody := []byte("test message")
	person := &person_api.Person{
		SSHPublicKeys: person_api.StandardAttributeValues{
			Values: map[string]interface{}{
				"key_one": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1BP2MqjpXMCUUBtdcPefr9RymkT1yV+l9y5S0I2JFc test_fixture_ed25519",
				"key_two": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDOSSQZw8tPFls6SzkyeElSk/MobGPUlvNQsMfMJCzcsHRM1BpCA3DQT3XrcUaO/OoXbYbScqxSCUEaeeFMwCog832Pjypsq/hs9qQbtK2D9lBJzUDiJzxGPMQEJ/QOW533yu+jJd7CTePTen/tKeqyqQdu/8hm92ZiP473ztKiQPLH3gfoT6iia8ZgzlHq/fsbv+O/A6FVOkYDauLOtYpGTI3z/QnL9DnpvT27et5xtKP7Q6ZKOAJnCBbeK1QIqbg+JrTNk5toM/jbssVN/I+fDruSeyvpK2bEmPe4fHJTazK+w8bOOIE8J4aaMfiNpvAoN6HywCY1l+TeE1oolj7RoivwEfFL8VV4sXigG3s8SCLlKvXPT8J5m6eY9DJXSmvKxcIRMIIj695ETlZ/rO0Cy83oLnOViIQbkzO5mlApNWeAMgGD6iSVJcqv5lLW5VkCk3NZxw3kF4eew0Sw0a5UveD5qHH1cWPeete+lX+cW2KkQzCtvW2ns8VzMZtQOROqPjJyikKU2CLeI/VRZB5PKe1liBgYOhUZeotXBe6prdGFoRhL6N+H3kk8K3BQqnJTYxpamT2Wc8ESxdNDMCzqmn47bIx1gKYBKulg4OK6F6kAjdy/lFiqoFuMYValdYVpTtR98jhaYwSY9pCzqaSg4pGtXNMstBxm4dvLW74OaQ== test_fixture_rsa4096",
			},
		},
	}

	out, err := AgeEncryptMailBody(origBody, person)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.Contains(t, string(out), "-----BEGIN AGE ENCRYPTED FILE-----")
	assert.Contains(t, string(out), "-----END AGE ENCRYPTED FILE-----")
}
