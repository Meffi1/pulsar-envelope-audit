package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func TestSealOpenEnvelope_CrossCommitteeReplay(t *testing.T) {
	dealerKey, err := GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var dealer, recipient NodeID
	copy(dealer[:], dealerKey.KEMPub[:32])
	copy(recipient[:], recipientKey.KEMPub[:32])

	var committeeRootA, committeeRootB [32]byte
	copy(committeeRootA[:], "committee-root-A-fixed-for-test!!")
	copy(committeeRootB[:], "committee-root-B-fixed-for-test!!")
	if bytes.Equal(committeeRootA[:], committeeRootB[:]) {
		t.Fatal("test setup: committee roots must differ")
	}

	var share [64]byte
	for i := range share {
		share[i] = byte(i)
	}
	var contribution [SeedSize]byte
	for i := range contribution {
		contribution[i] = byte(i ^ 0x55)
	}
	var encapSeed [64]byte
	if _, err := rand.Read(encapSeed[:]); err != nil {
		t.Fatal(err)
	}
	encapSeedSlice := encapSeed[:mlkem768.EncapsulationSeedSize]

	env, err := sealEnvelope(dealer, recipient, committeeRootA,
		share[:], contribution, recipientKey.PublicKey().KEMPub, encapSeedSlice)
	if err != nil {
		t.Fatalf("sealEnvelope: %v", err)
	}

	gotShare, gotContrib, err := sealOpenEnvelope(dealer, recipient, committeeRootA, env, len(share), recipientKey)
	if err != nil {
		t.Fatalf("legitimate open with same committee root: %v", err)
	}
	if !bytes.Equal(gotShare, share[:]) {
		t.Fatal("share round-trip mismatch")
	}
	if gotContrib != contribution {
		t.Fatal("contribution round-trip mismatch")
	}

	_, _, err = sealOpenEnvelope(dealer, recipient, committeeRootB, env, len(share), recipientKey)
	if err != ErrEnvelopeAuthBad {
		t.Fatalf("cross-committee replay: expected ErrEnvelopeAuthBad, got %v", err)
	}
}

func TestSealEnvelope_EncapSeedReuse(t *testing.T) {
	recipientKey, err := GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var dealer, recipient NodeID
	copy(dealer[:], "dealer-id-32-bytes-padding-here!!")
	copy(recipient[:], "recipient-id-32-bytes-padding-here!!")

	var committeeRoot [32]byte
	copy(committeeRoot[:], "committee-root-fixed-for-test!!")

	var share1, share2 [64]byte
	for i := range share1 {
		share1[i] = byte(i)
		share2[i] = byte(i ^ 0xFF)
	}
	var contribution [SeedSize]byte
	copy(contribution[:], "contribution-32-bytes-padding-here!")

	var encapSeed [64]byte
	copy(encapSeed[:], "same-encap-seed-for-both-envelopes!!!!")
	encapSeedSlice := encapSeed[:mlkem768.EncapsulationSeedSize]

	env1, err := sealEnvelope(dealer, recipient, committeeRoot, share1[:], contribution, recipientKey.PublicKey().KEMPub, encapSeedSlice)
	if err != nil {
		t.Fatalf("sealEnvelope 1: %v", err)
	}
	env2, err := sealEnvelope(dealer, recipient, committeeRoot, share2[:], contribution, recipientKey.PublicKey().KEMPub, encapSeedSlice)
	if err != nil {
		t.Fatalf("sealEnvelope 2: %v", err)
	}

	if bytes.Equal(env1.Sealed, env2.Sealed) {
		t.Fatal("sealed payloads are identical despite different shares — this is a problem!")
	}

}

