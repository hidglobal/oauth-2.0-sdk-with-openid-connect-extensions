package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the scope class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ScopeTest extends TestCase {


	public void testRun() {

		Scope scope = new Scope();

		scope.add(new ScopeValue("read"));
		scope.add(new ScopeValue("write"));

		assertEquals(2, scope.size());

		String out = scope.toString();

		System.out.println("Scope: " + out);

		Scope scopeParsed = Scope.parse(out);

		assertEquals(2, scopeParsed.size());

		assertTrue(scope.equals(scopeParsed));
	}


	public void testInequality() {

		Scope s1 = Scope.parse("read");
		Scope s2 = Scope.parse("write");

		assertFalse(s1.equals(s2));
	}


	public void testParseNull() {

		assertNull(Scope.parse(null));
	}


	public void testParseEmptyString() {

		Scope s = Scope.parse("");

		assertEquals(0, s.size());
	}
}
