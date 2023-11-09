/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v3/json"
)

// rawJSONWebEncryption represents a raw JWE JSON object. Used for parsing/serializing.
type rawJSONWebEncryption struct {
	Protected    *byteBuffer        `json:"protected,omitempty"`
	Unprotected  *rawHeader         `json:"unprotected,omitempty"`
	Header       *rawHeader         `json:"header,omitempty"`
	Recipients   []rawRecipientInfo `json:"recipients,omitempty"`
	Aad          *byteBuffer        `json:"aad,omitempty"`
	EncryptedKey *byteBuffer        `json:"encrypted_key,omitempty"`
	Iv           *byteBuffer        `json:"iv,omitempty"`
	Ciphertext   *byteBuffer        `json:"ciphertext,omitempty"`
	Tag          *byteBuffer        `json:"tag,omitempty"`
}

// rawRecipientInfo represents a raw JWE Per-Recipient header JSON object. Used for parsing/serializing.
type rawRecipientInfo struct {
	Header       *rawHeader `json:"header,omitempty"`
	EncryptedKey string     `json:"encrypted_key,omitempty"`
}

// JSONWebEncryption represents an encrypted JWE object after parsing.
type JSONWebEncryption struct {
	Header                   Header
	protected, unprotected   *rawHeader
	recipients               []recipientInfo
	cipher                   contentCipher
	aad, iv, ciphertext, tag []byte
	original                 *rawJSONWebEncryption
}

// recipientInfo represents a JWE Per-Recipient header JSON object after parsing, sanitizing,
// and merging with the protected and unprotected headers.
type recipientInfo struct {
	header       Header
	encryptedKey []byte
}

// GetAuthData retrieves the (optional) authenticated data attached to the object.
func (obj JSONWebEncryption) GetAuthData() []byte {
	if obj.aad != nil {
		out := make([]byte, len(obj.aad))
		copy(out, obj.aad)
		return out
	}

	return nil
}

// merge a sequence of rawHeader sets into one.
//
// Values in earlier parameters override values in later parameters.
func mergeHeaders(headers ...*rawHeader) rawHeader {
	out := rawHeader{}
	for _, header := range headers {
		out.merge(header)
	}
	return out
}

// Get the additional authenticated data from a JWE object.
func (obj JSONWebEncryption) computeAuthData() []byte {
	var protected string

	switch {
	case obj.original != nil && obj.original.Protected != nil:
		protected = obj.original.Protected.base64()
	case obj.protected != nil:
		protected = base64.RawURLEncoding.EncodeToString(mustSerializeJSON((obj.protected)))
	default:
		protected = ""
	}

	output := []byte(protected)
	if obj.aad != nil {
		output = append(output, '.')
		output = append(output, []byte(base64.RawURLEncoding.EncodeToString(obj.aad))...)
	}

	return output
}

type JWEParser struct {
	// invariant: the allowedKeyAlgorithms and allowedContentEncryption slices
	// always have length >= 1.
	allowedKeyAlgorithms     []KeyAlgorithm
	allowedContentEncryption []ContentEncryption
}

// NewJWEParser creates a new JWE parser with the given validation options.
func NewJWEParser(keyAlgorithm KeyAlgorithm, contentEncryption ContentEncryption) *JWEParser {
	return &JWEParser{
		allowedKeyAlgorithms:     []KeyAlgorithm{keyAlgorithm},
		allowedContentEncryption: []ContentEncryption{contentEncryption},
	}
}

// valid implements the private `headerValidator` interface.
//
// It checks that the "alg" and "enc" headers have allowed values.
func (p *JWEParser) valid(name, value string) error {
	switch name {
	case headerAlgorithm:
		for _, alg := range p.allowedKeyAlgorithms {
			if KeyAlgorithm(value) == alg {
				return nil
			}
		}
		return fmt.Errorf("expected \"alg\" to be one of %v, got %q", p.allowedKeyAlgorithms, value)
	case headerEncryption:
		for _, alg := range p.allowedContentEncryption {
			if ContentEncryption(value) == alg {
				return nil
			}
		}
		return fmt.Errorf("expected \"enc\" to be one of %v, got %q", p.allowedContentEncryption, value)
	}
	return nil
}

// Parse parses an encrypted message in compact or JWE JSON Serialization format.
func (p *JWEParser) Parse(input string) (*JSONWebEncryption, error) {
	input = stripWhitespace(input)
	if strings.HasPrefix(input, "{") {
		return p.parseEncryptedFull(input)
	}

	return p.parseEncryptedCompact(input)
}

// parseEncryptedFull parses a message in compact format.
func (p *JWEParser) parseEncryptedFull(input string) (*JSONWebEncryption, error) {
	var parsed rawJSONWebEncryption
	err := json.Unmarshal([]byte(input), &parsed)
	if err != nil {
		return nil, err
	}

	return p.sanitize(&parsed)
}

// sanitized produces a cleaned-up JWE object from the raw JSON.
func (p *JWEParser) sanitize(parsed *rawJSONWebEncryption) (*JSONWebEncryption, error) {
	// Check that there is not a nonce in the unprotected headers
	if parsed.Unprotected != nil {
		if nonce := parsed.Unprotected.getNonce(); nonce != "" {
			return nil, ErrUnprotectedNonce
		}
	}
	if parsed.Header != nil {
		if nonce := parsed.Header.getNonce(); nonce != "" {
			return nil, ErrUnprotectedNonce
		}
	}

	var protected rawHeader
	if parsed.Protected != nil && len(parsed.Protected.bytes()) > 0 {
		err := json.Unmarshal(parsed.Protected.bytes(), &protected)
		if err != nil {
			return nil, fmt.Errorf("go-jose/go-jose: invalid protected header: %s, %s", err, parsed.Protected.base64())
		}
	}

	// Note: this must be called _after_ we parse the protected header,
	// otherwise fields from the protected header will not get picked up.
	var err error
	mergedHeaders := mergeHeaders(&protected, parsed.Unprotected)

	if crit := mergedHeaders[headerCritical]; crit != nil && len(*crit) > 0 {
		return nil, fmt.Errorf("go-jose/go-jose: unsupported crit header")
	}

	cipher := getContentCipher(mergedHeaders.getEncryption())
	if cipher == nil {
		return nil, fmt.Errorf("go-jose/go-jose: unsupported enc value '%s'", string(mergedHeaders.getEncryption()))
	}

	mergedAndSanitized, err := mergedHeaders.sanitized(p)
	if err != nil {
		return nil, fmt.Errorf("go-jose/go-jose: cannot sanitize merged headers: %v (%v)", err, mergedHeaders)
	}

	var recipients []recipientInfo
	if len(parsed.Recipients) == 0 {
		header, err := parsed.Header.sanitized(p)
		if err != nil {
			return nil, fmt.Errorf("go-jose/go-jose: cannot sanitize recipient headers: %v (%v)", err, parsed.Header)
		}
		recipients = []recipientInfo{
			{
				header:       header,
				encryptedKey: parsed.EncryptedKey.bytes(),
			},
		}
	} else {
		recipients = make([]recipientInfo, 0, len(parsed.Recipients))
		for _, rawRecipient := range parsed.Recipients {
			encryptedKey, err := base64URLDecode(rawRecipient.EncryptedKey)
			if err != nil {
				return nil, err
			}

			// Check that there is not a nonce in the unprotected header
			if rawRecipient.Header != nil && rawRecipient.Header.getNonce() != "" {
				return nil, ErrUnprotectedNonce
			}

			header, err := rawRecipient.Header.sanitized(p)
			if err != nil {
				return nil, fmt.Errorf("go-jose/go-jose: cannot sanitize recipient headers: %v (%v)", err, parsed.Header)
			}

			if header.Algorithm == "" || header.ExtraHeaders[headerEncryption] == nil {
				return nil, fmt.Errorf("go-jose/go-jose: message is missing alg/enc headers")
			}

			recipients = append(recipients, recipientInfo{
				header:       header,
				encryptedKey: encryptedKey,
			})
		}
	}

	return &JSONWebEncryption{
		Header:      mergedAndSanitized,
		protected:   &protected,
		unprotected: parsed.Unprotected,
		recipients:  recipients,

		cipher:     cipher,
		aad:        parsed.Aad.bytes(),
		iv:         parsed.Iv.bytes(),
		ciphertext: parsed.Ciphertext.bytes(),
		tag:        parsed.Tag.bytes(),

		original: parsed,
	}, nil
}

// parseEncryptedCompact parses a message in compact format.
func (p *JWEParser) parseEncryptedCompact(input string) (*JSONWebEncryption, error) {
	parts := strings.Split(input, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("go-jose/go-jose: compact JWE format must have five parts")
	}

	rawProtected, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, err
	}

	encryptedKey, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}

	iv, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64URLDecode(parts[3])
	if err != nil {
		return nil, err
	}

	tag, err := base64URLDecode(parts[4])
	if err != nil {
		return nil, err
	}

	raw := &rawJSONWebEncryption{
		Protected:    newBuffer(rawProtected),
		EncryptedKey: newBuffer(encryptedKey),
		Iv:           newBuffer(iv),
		Ciphertext:   newBuffer(ciphertext),
		Tag:          newBuffer(tag),
	}

	return raw.sanitized()
}

// CompactSerialize serializes an object using the compact serialization format.
func (obj JSONWebEncryption) CompactSerialize() (string, error) {
	if len(obj.recipients) != 1 || obj.unprotected != nil ||
		obj.protected == nil || obj.recipients[0].header != nil {
		return "", ErrNotSupported
	}

	serializedProtected := mustSerializeJSON(obj.protected)

	return fmt.Sprintf(
		"%s.%s.%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(serializedProtected),
		base64.RawURLEncoding.EncodeToString(obj.recipients[0].encryptedKey),
		base64.RawURLEncoding.EncodeToString(obj.iv),
		base64.RawURLEncoding.EncodeToString(obj.ciphertext),
		base64.RawURLEncoding.EncodeToString(obj.tag)), nil
}

// FullSerialize serializes an object using the full JSON serialization format.
func (obj JSONWebEncryption) FullSerialize() string {
	raw := rawJSONWebEncryption{
		Unprotected:  obj.unprotected,
		Iv:           newBuffer(obj.iv),
		Ciphertext:   newBuffer(obj.ciphertext),
		EncryptedKey: newBuffer(obj.recipients[0].encryptedKey),
		Tag:          newBuffer(obj.tag),
		Aad:          newBuffer(obj.aad),
		Recipients:   []rawRecipientInfo{},
	}

	if len(obj.recipients) > 1 {
		for _, recipient := range obj.recipients {
			info := rawRecipientInfo{
				Header:       recipient.header,
				EncryptedKey: base64.RawURLEncoding.EncodeToString(recipient.encryptedKey),
			}
			raw.Recipients = append(raw.Recipients, info)
		}
	} else {
		// Use flattened serialization
		raw.Header = obj.recipients[0].header
		raw.EncryptedKey = newBuffer(obj.recipients[0].encryptedKey)
	}

	if obj.protected != nil {
		raw.Protected = newBuffer(mustSerializeJSON(obj.protected))
	}

	return string(mustSerializeJSON(raw))
}
