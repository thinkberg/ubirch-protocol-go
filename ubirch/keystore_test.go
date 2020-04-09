package ubirch

import (
	"bytes"
	"testing"
)

func TestEncryptedKeystore(t *testing.T) {
	var correctSecret = []byte("1234567890123456")
	var wrongSecret = []byte("0234567890123456")
	var keyValue = []byte("super secret")
	const keyName = "44735d56-e2d3-4577-be48-3ffb4033debd"

	// can initialize new Keystore
	ks := NewEncryptedKeystore(correctSecret)
	if ks == nil {
		t.Error("Newly initialized keystore is nil")
	}

	// can store key
	if err := ks.SetKey(keyName, keyValue); err != nil {
		t.Errorf("Error setting key %q: %s", keyName, err)
	}

	// can marshal keystore into byte representation
	byteRepr, err := ks.MarshalJSON()

	if err != nil {
		t.Errorf("error while serializing KeyStore: %s", err)
	}

	t.Run("Can load keystore", func(t *testing.T) {
		ks := NewEncryptedKeystore(correctSecret)
		if err := ks.UnmarshalJSON(byteRepr); err != nil {
			t.Errorf("Error loading keystore: %s", err)
		}

		retrieved, err := ks.GetKey(keyName)
		if err != nil {
			t.Errorf("Error getting key %q: %s", keyName, err)
		}
		if !bytes.Equal(keyValue, retrieved) {
			t.Errorf("Error getting key %q: retrieved: %x expected: %x", keyName, retrieved, keyValue)
		}
	})

	t.Run("Can not load keystore with wrong secret", func(t *testing.T) {
		ks := NewEncryptedKeystore(wrongSecret)
		if err := ks.UnmarshalJSON(byteRepr); err != nil {
			t.Errorf("Error loading keystore: %s", err)
		}

		_, err := ks.GetKey(keyName)
		if err == nil {
			t.Errorf("Succeeded in getting key with wrong password.")
		}
	})

}
