package main

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/sha3"
)

// --- Заглушки типов, которые есть в pulsar ---

type NodeID [32]byte

const SeedSize = 32

const (
	envelopeAuthTagSize  = 32
	dkgEnvelopeKeyTag    = "PULSAR/dkg-envelope-key/v1"
	dkgEnvelopeStreamTag = "PULSAR/dkg-envelope-stream/v1"
	dkgEnvelopeAuthTag   = "PULSAR/dkg-envelope-auth/v1"
)

type DKGShareEnvelope struct {
	KEMCiphertext []byte
	Sealed        []byte
}

// IdentityKey — упрощённая версия: храним только KEM-ключи.
type IdentityKey struct {
	KEMPriv []byte
	KEMPub  []byte
}

func (id *IdentityKey) PublicKey() *IdentityKey {
	return &IdentityKey{KEMPub: id.KEMPub}
}

var (
	ErrEnvelopeAuthBad    = errors.New("pulsar: envelope auth tag mismatch")
	ErrEnvelopeCiphertext = errors.New("pulsar: bad envelope ciphertext")
	ErrSessionIdentityPK  = errors.New("pulsar: bad recipient KEM public key")
	ErrIdentityKeyMissing = errors.New("pulsar: identity key missing")
	ErrIdentityCorrupted  = errors.New("pulsar: identity key corrupted")
)

// GenerateIdentity — генерирует ML-KEM-768 пару.
func GenerateIdentity(r io.Reader) (*IdentityKey, error) {
	pk, sk, err := mlkem768.GenerateKeyPair(r)
	if err != nil {
		return nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &IdentityKey{KEMPriv: skBytes, KEMPub: pkBytes}, nil
}

// --- Вспомогательные функции (упрощённые версии из pulsar) ---

func kmac256(key, input []byte, outLen int, tag string) []byte {
	h := sha3.NewCShake256([]byte(tag), nil)
	h.Write(key)
	h.Write(input)
	out := make([]byte, outLen)
	h.Read(out)
	return out
}

func cshake256(key []byte, outLen int, tag string) []byte {
	h := sha3.NewCShake256([]byte(tag), nil)
	h.Write(key)
	out := make([]byte, outLen)
	h.Read(out)
	return out
}

func ctEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func deriveEnvelopeKey(ss []byte, dealerID, recipientID NodeID, committeeRoot [32]byte) [32]byte {
	info := append([]byte(dkgEnvelopeKeyTag), dealerID[:]...)
	info = append(info, recipientID[:]...)
	info = append(info, committeeRoot[:]...)
	h := sha3.NewCShake256(info, nil)
	h.Write(ss)
	var out [32]byte
	h.Read(out[:])
	return out
}

// --- Основные функции (скопированы из pulsar с минимальными правками) ---

func sealEnvelope(
	dealerID, recipientID NodeID,
	committeeRoot [32]byte,
	shareWire []byte,
	contribution [SeedSize]byte,
	recipientKEMPub []byte,
	encapSeed []byte,
) (DKGShareEnvelope, error) {
	if len(recipientKEMPub) != mlkem768.PublicKeySize {
		return DKGShareEnvelope{}, ErrSessionIdentityPK
	}
	if len(encapSeed) != mlkem768.EncapsulationSeedSize {
		return DKGShareEnvelope{}, ErrEnvelopeCiphertext
	}
	if len(shareWire) == 0 {
		return DKGShareEnvelope{}, ErrEnvelopeCiphertext
	}
	var pk mlkem768.PublicKey
	if err := pk.Unpack(recipientKEMPub); err != nil {
		return DKGShareEnvelope{}, ErrSessionIdentityPK
	}
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(ct, ss, encapSeed)

	kEnv := deriveEnvelopeKey(ss, dealerID, recipientID, committeeRoot)

	sealedSize := len(shareWire) + SeedSize + envelopeAuthTagSize
	plaintext := make([]byte, sealedSize)
	copy(plaintext[:len(shareWire)], shareWire)
	copy(plaintext[len(shareWire):len(shareWire)+SeedSize], contribution[:])
	authInput := append(append([]byte{}, dealerID[:]...), recipientID[:]...)
	authInput = append(authInput, shareWire...)
	authInput = append(authInput, contribution[:]...)
	tag := kmac256(kEnv[:], authInput, envelopeAuthTagSize, dkgEnvelopeAuthTag)
	copy(plaintext[len(shareWire)+SeedSize:], tag)

	stream := cshake256(kEnv[:], sealedSize, dkgEnvelopeStreamTag)
	sealed := make([]byte, sealedSize)
	for i := 0; i < sealedSize; i++ {
		sealed[i] = plaintext[i] ^ stream[i]
	}

	return DKGShareEnvelope{
		KEMCiphertext: ct,
		Sealed:        sealed,
	}, nil
}

func sealOpenEnvelope(
	dealerID, recipientID NodeID,
	committeeRoot [32]byte,
	env DKGShareEnvelope,
	shareWireLen int,
	myIdentity *IdentityKey,
) (shareWire []byte, contribution [SeedSize]byte, err error) {
	if myIdentity == nil {
		err = ErrIdentityKeyMissing
		return
	}
	if len(env.KEMCiphertext) != mlkem768.CiphertextSize {
		err = ErrEnvelopeCiphertext
		return
	}
	if shareWireLen <= 0 {
		err = ErrEnvelopeCiphertext
		return
	}
	sealedSize := shareWireLen + SeedSize + envelopeAuthTagSize
	if len(env.Sealed) != sealedSize {
		err = ErrEnvelopeCiphertext
		return
	}
	var sk mlkem768.PrivateKey
	if e := sk.Unpack(myIdentity.KEMPriv); e != nil {
		err = ErrIdentityCorrupted
		return
	}
	ss := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ss, env.KEMCiphertext)

	kEnv := deriveEnvelopeKey(ss, dealerID, recipientID, committeeRoot)
	stream := cshake256(kEnv[:], sealedSize, dkgEnvelopeStreamTag)
	plaintext := make([]byte, sealedSize)
	for i := 0; i < sealedSize; i++ {
		plaintext[i] = env.Sealed[i] ^ stream[i]
	}
	gotShare := make([]byte, shareWireLen)
	var gotContrib [SeedSize]byte
	copy(gotShare, plaintext[:shareWireLen])
	copy(gotContrib[:], plaintext[shareWireLen:shareWireLen+SeedSize])
	authInput := append(append([]byte{}, dealerID[:]...), recipientID[:]...)
	authInput = append(authInput, gotShare...)
	authInput = append(authInput, gotContrib[:]...)
	expectedTag := kmac256(kEnv[:], authInput, envelopeAuthTagSize, dkgEnvelopeAuthTag)
	if !ctEqualSlice(expectedTag, plaintext[shareWireLen+SeedSize:]) {
		err = ErrEnvelopeAuthBad
		return
	}
	shareWire = gotShare
	contribution = gotContrib
	return
}