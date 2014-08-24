package com.nimbusds.oauth2.sdk;


import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the SAML 2.0 bearer grant.
 */
public class SAML2BearerGrantTest extends TestCase {


	public void testConstructorAndParser()
		throws Exception {

		Base64URL assertion = new Base64URL("abc"); // dummy XML assertion

		SAML2BearerGrant grant = new SAML2BearerGrant(assertion);
		assertEquals(GrantType.SAML2_BEARER, grant.getType());
		assertEquals(assertion, grant.getSAML2Assertion());
		assertEquals("abc", grant.getAssertion());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.SAML2_BEARER.getValue(), params.get("grant_type"));
		assertEquals("abc", params.get("assertion"));
		assertEquals(2, params.size());

		grant = SAML2BearerGrant.parse(params);
		assertEquals(GrantType.SAML2_BEARER, grant.getType());
		assertEquals("abc", grant.getSAML2Assertion().toString());
		assertEquals("abc", grant.getAssertion());
	}
}
