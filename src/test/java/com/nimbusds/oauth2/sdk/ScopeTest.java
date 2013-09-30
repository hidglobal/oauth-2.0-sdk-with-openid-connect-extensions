package com.nimbusds.oauth2.sdk;


import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;


/**
 * Tests the scope class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ScopeTest extends TestCase {


	public void testRun() {

		Scope scope = new Scope();

		scope.add(new Scope.Value("read"));
		scope.add(new Scope.Value("write"));

		assertEquals(2, scope.size());

		String out = scope.toString();

		System.out.println("Scope: " + out);
		
		assertEquals("read write", out);

		Scope scopeParsed = Scope.parse(out);

		assertEquals(2, scopeParsed.size());

		assertTrue(scope.equals(scopeParsed));
	}
	
	
	public void testListSerializationAndParsing() {
		
		Scope scope = Scope.parse("read write");
		
		List<String> list = scope.toStringList();
		
		assertEquals("read", list.get(0));
		assertEquals("write", list.get(1));
		assertEquals(2, list.size());
		
		assertEquals("read write", Scope.parse(list).toString());
	}


	public void testInequality() {

		Scope s1 = Scope.parse("read");
		Scope s2 = Scope.parse("write");

		assertFalse(s1.equals(s2));
	}


	public void testParseNullString() {

		assertNull(Scope.parse((String)null));
	}
	
	
	public void testParseNullCollection() {

		assertNull(Scope.parse((Collection<String>)null));
	}


	public void testParseEmptyString() {

		Scope s = Scope.parse("");

		assertEquals(0, s.size());
	}
}
