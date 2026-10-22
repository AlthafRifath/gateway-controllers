/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package backendjwt

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/signing"
)

// fakeGatewaySigner stands in for the policy engine's signing service. It signs
// ES256 with its own key and sets kid, as the real service does; the policy
// never sees the key.
type fakeGatewaySigner struct {
	key   *ecdsa.PrivateKey
	kid   string
	calls int
}

func (f *fakeGatewaySigner) Sign([]byte) ([]byte, signing.KeyInfo, error) {
	return nil, signing.KeyInfo{}, errors.New("not used")
}

func (f *fakeGatewaySigner) SignJWS(payload []byte, opts signing.Options) (string, signing.KeyInfo, error) {
	f.calls++
	var claims jwt.MapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", signing.KeyInfo{}, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = f.kid
	token.Header["typ"] = opts.Type
	signed, err := token.SignedString(f.key)
	return signed, signing.KeyInfo{Kid: f.kid, Algorithm: signing.ES256}, err
}

func (f *fakeGatewaySigner) SignDetachedJWS([]byte, signing.Options) (signing.DetachedJWS, signing.KeyInfo, error) {
	return signing.DetachedJWS{}, signing.KeyInfo{}, errors.New("not used")
}

func (f *fakeGatewaySigner) ActiveKey() (signing.KeyInfo, bool) {
	return signing.KeyInfo{Kid: f.kid, Algorithm: signing.ES256}, true
}

func (f *fakeGatewaySigner) JWKS() ([]byte, string)         { return []byte(`{"keys":[]}`), `"x"` }
func (f *fakeGatewaySigner) JWKSCacheMaxAge() time.Duration { return time.Minute }

func installGatewaySigner(t *testing.T) *fakeGatewaySigner {
	t.Helper()
	key, _ := generateECKey(t)
	f := &fakeGatewaySigner{key: key, kid: "gw-key-1"}
	signing.Install(f)
	t.Cleanup(func() { signing.Install(nil) })
	return f
}

func generateToken(t *testing.T, p *BackendJWTPolicy, params map[string]interface{}) string {
	t.Helper()
	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice"})
	mods, ok := p.OnRequestHeaders(context.Background(), reqCtx, params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected UpstreamRequestHeaderModifications")
	}
	return mods.HeadersToSet[defaultHeader]
}

func parseWithKid(t *testing.T, tokenStr string, key *ecdsa.PublicKey) (*jwt.Token, jwt.MapClaims) {
	t.Helper()
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return key, nil },
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("verify with the gateway key: %v", err)
	}
	return token, token.Claims.(jwt.MapClaims)
}

func TestGatewaySigning_TakesPrecedenceOverPolicyKey(t *testing.T) {
	gw := installGatewaySigner(t)
	_, policyKeyPEM := generateRSAKey(t)
	p := newTestPolicy()

	tokenStr := generateToken(t, p, baseParams(policyKeyPEM)) // policy-level RSA key also configured

	token, claims := parseWithKid(t, tokenStr, &gw.key.PublicKey)
	if token.Header["kid"] != "gw-key-1" || token.Header["typ"] != "JWT" {
		t.Fatalf("header = %v, want kid gw-key-1 and typ JWT", token.Header)
	}
	if claims["sub"] != "alice" || claims["iss"] != "https://gateway.example.com" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestGatewaySigning_NoPolicyKeyNeeded(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"issuer": "https://gateway.example.com", "tokenExpiry": "15m"}

	if err := p.Validate(params); err != nil {
		t.Fatalf("Validate without signingKey: %v", err)
	}
	parseWithKid(t, generateToken(t, p, params), &gw.key.PublicKey)
}

func TestGatewaySigning_OverridesAlgorithmNone(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"algorithm": "NONE", "issuer": "gw"}

	parseWithKid(t, generateToken(t, p, params), &gw.key.PublicKey)
}

func TestGatewaySigning_ValidateStillChecksNonKeyParams(t *testing.T) {
	installGatewaySigner(t)
	p := newTestPolicy()
	if err := p.Validate(map[string]interface{}{"algorithm": "HS256"}); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}
	if err := p.Validate(map[string]interface{}{"tokenExpiry": "-1m"}); err == nil {
		t.Fatal("negative tokenExpiry accepted")
	}
}

// A token cached under one gateway key must not be served once another key signs.
func TestGatewaySigning_CacheIsKeyedBySigningKey(t *testing.T) {
	gw := installGatewaySigner(t)
	p := newTestPolicy()
	params := map[string]interface{}{"issuer": "gw"}

	first := generateToken(t, p, params)
	if again := generateToken(t, p, params); again != first || gw.calls != 1 {
		t.Fatalf("expected a cache hit for the same key (calls=%d)", gw.calls)
	}

	gw.kid = "gw-key-2"
	rotated := generateToken(t, p, params)
	if rotated == first || gw.calls != 2 {
		t.Fatalf("token signed by the previous key was served after rotation (calls=%d)", gw.calls)
	}
	token, _ := parseWithKid(t, rotated, &gw.key.PublicKey)
	if token.Header["kid"] != "gw-key-2" {
		t.Fatalf("kid = %v, want gw-key-2", token.Header["kid"])
	}
}

func TestGatewaySigning_FailureIs500(t *testing.T) {
	signing.Install(&failingSigner{})
	t.Cleanup(func() { signing.Install(nil) })
	p := newTestPolicy()

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, Subject: "alice"})
	resp, ok := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{}).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 500 {
		t.Fatalf("expected a 500 ImmediateResponse, got %#v", resp)
	}
}

type failingSigner struct{ fakeGatewaySigner }

func (failingSigner) SignJWS([]byte, signing.Options) (string, signing.KeyInfo, error) {
	return "", signing.KeyInfo{}, errors.New("hsm unavailable")
}

func (failingSigner) ActiveKey() (signing.KeyInfo, bool) {
	return signing.KeyInfo{Kid: "k", Algorithm: signing.ES256}, true
}

// With no gateway key installed the policy-level key signs as before, with no kid.
func TestPolicyKeySigning_UnchangedWithoutGatewayKey(t *testing.T) {
	signing.Install(nil)
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()

	tokenStr := generateToken(t, p, baseParams(keyPEM))
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return &rsaKey.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("verify with the policy key: %v", err)
	}
	if _, hasKid := token.Header["kid"]; hasKid {
		t.Fatal("policy-level signing must not add a kid")
	}
}

func TestHasPolicySigningKey(t *testing.T) {
	cases := map[string]struct {
		params map[string]interface{}
		want   bool
	}{
		"inline":  {map[string]interface{}{"signingKey": map[string]interface{}{"inline": "pem"}}, true},
		"path":    {map[string]interface{}{"signingKey": map[string]interface{}{"path": "/k.pem"}}, true},
		"empty":   {map[string]interface{}{"signingKey": map[string]interface{}{"inline": ""}}, false},
		"absent":  {map[string]interface{}{}, false},
		"invalid": {map[string]interface{}{"signingKey": "pem"}, false},
	}
	for name, tc := range cases {
		if got := hasPolicySigningKey(tc.params); got != tc.want {
			t.Errorf("%s: hasPolicySigningKey = %v, want %v", name, got, tc.want)
		}
	}
}
