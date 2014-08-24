package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Tests the password grant.
 */
public class ResourceOwnerPasswordCredentialsGrantTest extends TestCase {


	public void testConstructor() {

		String username = "alice";
		Secret password = new Secret("secret");
		ResourceOwnerPasswordCredentialsGrant grant = new ResourceOwnerPasswordCredentialsGrant(username, password);
		assertEquals(GrantType.PASSWORD, grant.getType());
		assertEquals(username, grant.getUsername());
		assertEquals(password, grant.getPassword());

		Map<String,String> params = grant.toParameters();
		assertEquals("password", params.get("grant_type"));
		assertEquals("alice", params.get("username"));
		assertEquals("secret", params.get("password"));
		assertEquals(3, params.size());
	}


	public void testParse()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "password");
		params.put("username", "alice");
		params.put("password", "secret");

		ResourceOwnerPasswordCredentialsGrant grant = ResourceOwnerPasswordCredentialsGrant.parse(params);
		assertEquals(GrantType.PASSWORD, grant.getType());
		assertEquals("alice", grant.getUsername());
		assertEquals("secret", grant.getPassword().getValue());
	}


	public void testParseMissingGrantType() {

		Map<String,String> params = new HashMap<>();
		params.put("username", "alice");
		params.put("password", "secret");

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testParseUnsupportedGrantType() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "invalid_grant");
		params.put("username", "alice");
		params.put("password", "secret");

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, e.getErrorObject());
		}
	}


	public void testParseMissingUsername() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "password");
		params.put("password", "secret");

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testParseMissingPassword() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "password");
		params.put("username", "alice");

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
}
