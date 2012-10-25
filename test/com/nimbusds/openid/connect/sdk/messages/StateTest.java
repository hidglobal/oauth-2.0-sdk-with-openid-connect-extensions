package com.nimbusds.openid.connect.sdk.messages;


import junit.framework.TestCase;


/**
 * Tests random state value generation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-23)
 */
public class StateTest extends TestCase {
	
	
	public void testGeneration() {
		
		State state = State.generate();
		
		System.out.println("Random state (default size): " + state);
		
		assertEquals(8, state.toString().length());
	}
	
	
	public void testGenerationVarLength() {
	
		State state = State.generate(16);
		
		System.out.println("Random state (16 chars): " + state);
		
		assertEquals(16, state.toString().length());
	}
}
