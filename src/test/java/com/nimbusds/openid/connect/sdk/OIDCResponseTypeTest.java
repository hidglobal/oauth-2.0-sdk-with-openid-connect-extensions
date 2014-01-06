package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;


/**
 * Tests the OpenID Connect response type value constants.
 */
public class OIDCResponseTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("id_token", OIDCResponseTypeValue.ID_TOKEN.getValue());
		assertEquals("none", OIDCResponseTypeValue.NONE.getValue());
	}
}
