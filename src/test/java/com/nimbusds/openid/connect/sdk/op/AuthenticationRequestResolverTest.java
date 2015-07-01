package com.nimbusds.openid.connect.sdk.op;


import junit.framework.TestCase;


/**
 * Tests the OpenID Connect authentication request resolver.
 */
public class AuthenticationRequestResolverTest extends TestCase {


	public void testMinimal()
		throws Exception {

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver();

		assertNull(resolver.getJWTDecoder());
		assertNull(resolver.getJWTRetriever());
	}
}
