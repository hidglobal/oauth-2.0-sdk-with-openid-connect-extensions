package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.AuthorizationCode;


/**
 * Tests the authorisation code hash.
 */
public class CodeHashTest extends TestCase {


	public void testComputeAgainstSpecExample() {

		AuthorizationCode code = new AuthorizationCode("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk");

		CodeHash computedHash = CodeHash.compute(code, JWSAlgorithm.RS256);

		CodeHash expectedHash = new CodeHash("LDktKdoQak3Pk0cnXxCltA");

		assertEquals(expectedHash.getValue(), computedHash.getValue());
	}


	public void testEquality() {

		AuthorizationCode code = new AuthorizationCode();

		CodeHash hash1 = CodeHash.compute(code, JWSAlgorithm.HS512);

		CodeHash hash2 = CodeHash.compute(code, JWSAlgorithm.HS512);

		assertTrue(hash1.equals(hash2));
	}


	public void testUnsupportedJWSAlg() {

		AuthorizationCode code = new AuthorizationCode();

		assertNull(CodeHash.compute(code, new JWSAlgorithm("no-such-alg")));
	}


	public void testIDTokenRequirement()
		throws Exception {

		// code flow
		// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code")));

		// implicit flow
		// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token")));
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token token")));

		// hybrid flow
		// http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		assertTrue(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token")));
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code token")));
		assertTrue(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token token")));
	}
}
