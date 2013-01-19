package com.nimbusds.oauth2.sdk.auth;


import junit.framework.TestCase;


/**
 * Tests the base abstract JWT authentication class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
public class JWTAuthenticationTest extends TestCase {


	public void testAssertionTypeConstant() {
	
		assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", 
			     JWTAuthentication.CLIENT_ASSERTION_TYPE);
	}
}
