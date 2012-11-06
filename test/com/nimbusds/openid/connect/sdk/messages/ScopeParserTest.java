package com.nimbusds.openid.connect.sdk.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Tests scope parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-06)
 */
public class ScopeParserTest extends TestCase {
	
	
	public void testParseStdAllGood() {
	
		String str = "openid profile email address phone";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = sp.parse(str);
		
		assertEquals(5, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(ScopeToken.OPENID));
		assertTrue(scope.contains(ScopeToken.PROFILE));
		assertTrue(scope.contains(ScopeToken.EMAIL));
		assertTrue(scope.contains(ScopeToken.ADDRESS));
		assertTrue(scope.contains(ScopeToken.PHONE));
	}
	
	
	public void testParseStdSelectedGood() {
	
		String str = "openid email phone";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = sp.parse(str);
		
		assertEquals(3, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(ScopeToken.OPENID));
		assertTrue(scope.contains(ScopeToken.EMAIL));
		assertTrue(scope.contains(ScopeToken.PHONE));
	}
	
	
	public void testParseStrictStdSelectedGood() {
	
		String str = "openid email phone";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = null;
		
		try {
			scope = sp.parseStrict(str);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(ScopeToken.OPENID));
		assertTrue(scope.contains(ScopeToken.EMAIL));
		assertTrue(scope.contains(ScopeToken.PHONE));
	}
	
	
	public void testParseStrictStdSelectedBad() {
	
		String str = "openid email phone xyz";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = sp.parse(str);
		
		assertEquals(3, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(ScopeToken.OPENID));
		assertTrue(scope.contains(ScopeToken.EMAIL));
		assertTrue(scope.contains(ScopeToken.PHONE));
	}
	
	
	public void testParseStdSelectedBadWithException() {
	
		String str = "openid email phone xyz";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = null;
		
		try {
			scope = sp.parseStrict(str);
			
			fail("Failed to raise parse exception");
			
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testParseStrictMissingOpenID() {
	
		String str = "email phone xyz";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = null;
		
		try {
			scope = sp.parseStrict(str);
			
			fail("Failed to raise parse exception");
			
		} catch (ParseException e) {
		
			// ok
		}
	}
}
