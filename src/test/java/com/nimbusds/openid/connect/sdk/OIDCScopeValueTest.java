package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import net.minidev.json.JSONObject;


/**
 * Tests the OpenID Connect scope value class.
 */
public class OIDCScopeValueTest extends TestCase {


	public void testValues() {

		assertEquals("openid", OIDCScopeValue.OPENID.getValue());
		assertEquals("profile", OIDCScopeValue.PROFILE.getValue());
		assertEquals("email", OIDCScopeValue.EMAIL.getValue());
		assertEquals("address", OIDCScopeValue.ADDRESS.getValue());
		assertEquals("phone", OIDCScopeValue.PHONE.getValue());
		assertEquals("offline_access", OIDCScopeValue.OFFLINE_ACCESS.getValue());

		assertEquals(6, OIDCScopeValue.values().length);
	}


	public void testToClaimsRequestJSON() {

		JSONObject o = OIDCScopeValue.OPENID.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("sub"));
		assertTrue((Boolean)((JSONObject)o.get("sub")).get("essential"));
		assertEquals(1, o.size());

		o = OIDCScopeValue.PROFILE.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("name"));
		assertNull(o.get("name"));
		assertTrue(o.containsKey("family_name"));
		assertNull(o.get("family_name"));
		assertTrue(o.containsKey("given_name"));
		assertNull(o.get("given_name"));
		assertTrue(o.containsKey("middle_name"));
		assertNull(o.get("middle_name"));
		assertTrue(o.containsKey("nickname"));
		assertNull(o.get("nickname"));
		assertTrue(o.containsKey("preferred_username"));
		assertNull(o.get("preferred_username"));
		assertTrue(o.containsKey("profile"));
		assertNull(o.get("profile"));
		assertTrue(o.containsKey("picture"));
		assertNull(o.get("picture"));
		assertTrue(o.containsKey("website"));
		assertNull(o.get("website"));
		assertTrue(o.containsKey("gender"));
		assertNull(o.get("gender"));
		assertTrue(o.containsKey("birthdate"));
		assertNull(o.get("birthdate"));
		assertTrue(o.containsKey("zoneinfo"));
		assertNull(o.get("zoneinfo"));
		assertTrue(o.containsKey("locale"));
		assertNull(o.get("locale"));
		assertTrue(o.containsKey("updated_at"));
		assertNull(o.get("updated_at"));
		assertEquals(14, o.size());

		o = OIDCScopeValue.EMAIL.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("email"));
		assertNull(o.get("email"));
		assertTrue(o.containsKey("email_verified"));
		assertNull(o.get("email_verified"));
		assertEquals(2, o.size());


		o = OIDCScopeValue.ADDRESS.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("address"));
		assertNull(o.get("address"));
		assertEquals(1, o.size());

		o = OIDCScopeValue.PHONE.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("phone_number"));
		assertNull(o.get("phone_number"));
		assertTrue(o.containsKey("phone_number_verified"));
		assertNull(o.get("phone_number_verified"));
		assertEquals(2, o.size());

		assertNull(OIDCScopeValue.OFFLINE_ACCESS.toClaimsRequestJSONObject());
	}
}
