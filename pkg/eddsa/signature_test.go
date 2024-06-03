package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uxuyprotocol/frost-ed25519/pkg/messages"
)

const sampleMessage = "This is a test for FROST"

func generateSignature() (*Signature, *PublicKey, error) {
	_, skBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sk, pk := newKeyPair(skBytes)
	skShare := NewSecretShare(0, sk)
	signature := skShare.sign([]byte(sampleMessage))
	return signature, pk, nil
}

func TestSignature_Verify(t *testing.T) {
	sig, pk, err := generateSignature()
	assert.NoError(t, err, "failed to generate signature")

	// Check that signature verifies
	require.True(t, pk.Verify([]byte(sampleMessage), sig), "failed to validate signature")

	// Check using ed25519.Verify
	assert.True(t, ed25519.Verify(pk.ToEd25519(), []byte(sampleMessage), sig.ToEd25519()))
}

func TestSignatureEncode_Decode(t *testing.T) {
	var signatureOutput Signature

	signature, _, err := generateSignature()
	assert.NoError(t, err, "failed to generate signature")

	assert.NoError(t, messages.CheckFROSTMarshaler(signature, &signatureOutput))

	assert.Equal(t, 1, signature.R.Equal(&signatureOutput.R))
	assert.Equal(t, 1, signature.S.Equal(&signatureOutput.S))
}
