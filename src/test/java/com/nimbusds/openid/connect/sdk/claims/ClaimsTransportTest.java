package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;


/**
 * Tests the claims transport enumeration.
 */
public class ClaimsTransportTest extends TestCase {


	public void testConstants() {

		assertEquals("USERINFO", ClaimsTransport.USERINFO.name());
		assertEquals("ID_TOKEN", ClaimsTransport.ID_TOKEN.name());
		assertEquals(2, ClaimsTransport.values().length);
	}


	public void testDefault() {

		assertEquals(ClaimsTransport.USERINFO, ClaimsTransport.getDefault());
	}
}
