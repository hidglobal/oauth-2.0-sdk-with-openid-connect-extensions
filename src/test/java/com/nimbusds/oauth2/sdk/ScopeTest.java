package com.nimbusds.oauth2.sdk;


import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;


/**
 * Tests the scope class.
 */
public class ScopeTest extends TestCase {


	public void testCopyConstructor() {

		Scope scope = new Scope(Scope.parse("read write"));
		assertTrue(scope.contains("read"));
		assertTrue(scope.contains("write"));
		assertEquals(2, scope.size());
	}


	public void testCopyConstructorNull() {

		Scope scope = new Scope((Scope)null);
		assertTrue(scope.isEmpty());
	}


	public void testVarargConstructor() {

		Scope scope = new Scope(new Scope.Value("read"), new Scope.Value("write"));

		assertTrue(scope.contains(new Scope.Value("read")));
		assertTrue(scope.contains(new Scope.Value("write")));
		assertEquals(2, scope.size());
	}


	public void testStringVarargConstructor() {

		Scope scope = new Scope("read", "write");

		assertTrue(scope.contains(new Scope.Value("read")));
		assertTrue(scope.contains(new Scope.Value("write")));
		assertEquals(2, scope.size());
	}


	public void testRun() {

		Scope scope = new Scope();

		scope.add(new Scope.Value("read"));
		scope.add(new Scope.Value("write"));

		assertTrue(scope.contains(new Scope.Value("read")));
		assertTrue(scope.contains("read"));
		assertTrue(scope.contains(new Scope.Value("write")));
		assertTrue(scope.contains("write"));
		assertEquals(2, scope.size());

		assertFalse(scope.contains(new Scope.Value("no-such-value")));
		assertFalse(scope.contains("no-such-value"));

		String out = scope.toString();

		System.out.println("Scope: " + out);
		
		assertEquals("read write", out);

		Scope scopeParsed = Scope.parse(out);

		assertTrue(scope.contains(new Scope.Value("read")));
		assertTrue(scope.contains(new Scope.Value("write")));
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


	public void testAddString() {

		Scope scope = new Scope();

		assertTrue(scope.add("openid"));
		assertTrue(scope.contains("openid"));
		assertEquals(1, scope.size());

		assertFalse(scope.add("openid"));
		assertTrue(scope.contains("openid"));
		assertEquals(1, scope.size());
	}


	public void testParseCommaDelimited() {

		Scope scope = Scope.parse("read,write,admin");

		assertTrue(scope.contains("read"));
		assertTrue(scope.contains("write"));
		assertTrue(scope.contains("admin"));
		assertEquals(3, scope.size());
	}
}
