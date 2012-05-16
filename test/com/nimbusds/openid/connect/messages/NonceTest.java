package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;


/**
 * Tests random nonce generation.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-03-23)
 */
public class NonceTest extends TestCase {
	
	
	public void testGeneration() {
		
		Nonce nonce = Nonce.generate();
		
		System.out.println("Random nonce (default size): " + nonce);
		
		assertEquals(8, nonce.toString().length());
	}
	
	
	public void testGenerationVarLength() {
	
		Nonce nonce = Nonce.generate(16);
		
		System.out.println("Random nonce (16 chars): " + nonce);
		
		assertEquals(16, nonce.toString().length());
	}
}
