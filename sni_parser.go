package main

import (
	"golang.org/x/crypto/cryptobyte"
)

type ClientHello struct {
	SNI string
}

func ParseClientHello(record []byte) (c *ClientHello, ok bool) {
	c = &ClientHello{}

	in := cryptobyte.String(record)

	if !in.Skip(5) {
		return nil, false
	}

	var messageType uint8
	if !in.ReadUint8(&messageType) || messageType != 1 {
		return nil, false
	}

	var clientHello cryptobyte.String
	if !in.ReadUint24LengthPrefixed(&clientHello) || !in.Empty() {
		return nil, false
	}

	var legacyVersion uint16
	if !clientHello.ReadUint16(&legacyVersion) {
		return nil, false
	}

	var random []byte
	if !clientHello.ReadBytes(&random, 32) {
		return nil, false
	}

	var legacySessionID []byte
	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacySessionID)) {
		return nil, false
	}

	var ciphersuitesBytes cryptobyte.String
	if !clientHello.ReadUint16LengthPrefixed(&ciphersuitesBytes) {
		return nil, false
	}

	for !ciphersuitesBytes.Empty() {
		var ciphersuite uint16
		if !ciphersuitesBytes.ReadUint16(&ciphersuite) {
			return nil, false
		}
	}

	var legacyCompressionMethods []uint8
	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacyCompressionMethods)) {
		return nil, false
	}

	var extensionsBytes cryptobyte.String
	if !clientHello.ReadUint16LengthPrefixed(&extensionsBytes) {
		return nil, false
	}

	if !clientHello.Empty() {
		return nil, false
	}

	for !extensionsBytes.Empty() {
		var extType uint16
		if !extensionsBytes.ReadUint16(&extType) {
			return nil, false
		}

		var extData cryptobyte.String
		if !extensionsBytes.ReadUint16LengthPrefixed(&extData) {
			return nil, false
		}

		if extType == 0x0 {
			extData.Skip(5)
			c.SNI = string(extData)
		}
	}

	return c, true
}
