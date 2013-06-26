package com.nimbusds.oauth2.sdk.id;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;


/**
 * Tests random state value generation.
 *
 * @author Vladimir Dzhuvinov
 */
public class StateTest extends TestCase {
	

	public void testValueConstructor() {

		String value = "abc";

		State state = new State(value);

		assertEquals(value, state.getValue());
		assertEquals(value, state.toString());
	}


	public void testEmptyValue() {

		try {
			new State("");

			fail("Failed to raise exception");
		
		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testEquality() {

		State s1 = new State("abc");

		State s2 = new State("abc");

		assertTrue(s1.equals(s2));
	}


	public void testInequality() {

		State s1 = new State("abc");

		State s2 = new State("def");

		assertFalse(s1.equals(s2));
	}


	public void testInequalityNull() {

		State s1 = new State("abc");

		assertFalse(s1.equals(null));
	}


	public void testHashCode() {

		State s1 = new State("abc");

		State s2 = new State("abc");

		assertEquals(s1.hashCode(), s2.hashCode());
	}

	
	public void testGeneration() {
		
		State state = new State();
		
		System.out.println("Random state (default byte length): " + state);
		
		assertEquals(Identifier.DEFAULT_BYTE_LENGTH, Base64.decodeBase64(state.toString()).length);
	}
	
	
	public void testGenerationVarLength() {
	
		State state = new State(16);
		
		System.out.println("Random state (16 byte length): " + state);
		
		assertEquals(16, Base64.decodeBase64(state.toString()).length);
	}


	public void testJSONValue() {

		State state = new State("abc");

		String json = state.toJSONString();

		System.out.println("\"state\":" + json);

		assertEquals("\"abc\"", json);
	}
}
