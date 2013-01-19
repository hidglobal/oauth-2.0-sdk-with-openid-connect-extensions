package com.nimbusds.oauth2.sdk.id;


import junit.framework.TestCase;


/**
 * Tests random state value generation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
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
		
		System.out.println("Random state (default size): " + state);
		
		assertEquals(32, state.toString().length());
	}
	
	
	public void testGenerationVarLength() {
	
		State state = new State(16);
		
		System.out.println("Random state (16 chars): " + state);
		
		assertEquals(16, state.toString().length());
	}
}
