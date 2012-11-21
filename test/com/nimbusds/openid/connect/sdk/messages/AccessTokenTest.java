package com.nimbusds.openid.connect.sdk.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Tests the access token class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-21)
 */
public class AccessTokenTest extends TestCase {


	public void testMinimalConstructor() {
		
		AccessToken token = new AccessToken("abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getExpiration());
		assertNull(token.getScope());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());
	}


	public void testGenerate() {

		AccessToken token = AccessToken.generate(12);

		assertNotNull(token);

		assertEquals(12, token.getValue().length());
		assertEquals(0l, token.getExpiration());
		assertNull(token.getScope());

		System.out.println(token.toAuthorizationHeader());
	}


	public void testGenerateDefault() {

		AccessToken token = AccessToken.generate();

		assertNotNull(token);

		assertEquals(8, token.getValue().length());
		assertEquals(0l, token.getExpiration());
		assertNull(token.getScope());

		System.out.println(token.toAuthorizationHeader());
	}


	public void testFullConstructor() {
		
		AccessToken token = new AccessToken("abc", 1500, Scope.createMinimal());
		
		assertEquals("abc", token.getValue());
		assertEquals(1500l, token.getExpiration());
		assertTrue(token.getScope().containsAll(Scope.createMinimal()));
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());
	}
	
	
	public void testParse() {
	
		AccessToken token = null;
	
		try {
			token = AccessToken.parse("Bearer abc");
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getExpiration());
		assertNull(token.getScope());
	}
	
	
	public void testParseExceptionMissingBearerIdentifier() {
	
		AccessToken token = null;
	
		try {
			token = AccessToken.parse("abc");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			// ok
			System.out.println(e.getMessage());
		}
	}
	
	
	public void testParseExceptionMissingTokenValue() {
	
		AccessToken token = null;
	
		try {
			token = AccessToken.parse("Bearer ");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			// ok
			System.out.println(e.getMessage());
		}
	}
}
