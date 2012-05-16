package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;


/**
 * Tests scope parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-03-23)
 */
public class ScopeParserTest extends TestCase {
	
	
	public void testParseStdAllGood() {
	
		String str = "openid profile email address phone";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = sp.parse(str);
		
		assertEquals(5, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(StdScopeMember.OPENID));
		assertTrue(scope.contains(StdScopeMember.PROFILE));
		assertTrue(scope.contains(StdScopeMember.EMAIL));
		assertTrue(scope.contains(StdScopeMember.ADDRESS));
		assertTrue(scope.contains(StdScopeMember.PHONE));
	}
	
	
	public void testParseStdSelectedGood() {
	
		String str = "openid email phone";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = sp.parse(str);
		
		assertEquals(3, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(StdScopeMember.OPENID));
		assertTrue(scope.contains(StdScopeMember.EMAIL));
		assertTrue(scope.contains(StdScopeMember.PHONE));
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
	
		assertTrue(scope.contains(StdScopeMember.OPENID));
		assertTrue(scope.contains(StdScopeMember.EMAIL));
		assertTrue(scope.contains(StdScopeMember.PHONE));
	}
	
	
	public void testParseStrictStdSelectedBad() {
	
		String str = "openid email phone xyz";
		
		ScopeParser sp = new ScopeParser();
		
		Scope scope = sp.parse(str);
		
		assertEquals(3, scope.size());
		
		assertTrue(scope.isValid());
	
		assertTrue(scope.contains(StdScopeMember.OPENID));
		assertTrue(scope.contains(StdScopeMember.EMAIL));
		assertTrue(scope.contains(StdScopeMember.PHONE));
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
