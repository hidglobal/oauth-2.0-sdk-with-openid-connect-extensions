package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;


/**
 * Tests prompt names and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-03-23)
 */
public class PromptTest extends TestCase {
	
	
	public void testNames() {
	
		assertEquals("none", Prompt.Type.NONE.toString());
		assertEquals("login", Prompt.Type.LOGIN.toString());
		assertEquals("consent", Prompt.Type.CONSENT.toString());
		assertEquals("select_account", Prompt.Type.SELECT_ACCOUNT.toString());
	}
	
	
	public void testValidityChecking() {
	
		Prompt prompt = new Prompt();
		
		prompt.add(Prompt.Type.NONE);
		assertTrue(prompt.isValid());
		
		prompt.add(Prompt.Type.LOGIN);
		assertFalse(prompt.isValid());
		
		prompt.remove(Prompt.Type.NONE);
		assertTrue(prompt.isValid());
	}
	
	
	public void testParse() {
	
		String s = "login consent select_account";
		
		Prompt prompt = null;
		
		try {
			prompt = Prompt.parse(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
	
		assertFalse(prompt.contains(Prompt.Type.NONE));
		
		assertTrue(prompt.contains(Prompt.Type.LOGIN));
		assertTrue(prompt.contains(Prompt.Type.CONSENT));
		assertTrue(prompt.contains(Prompt.Type.SELECT_ACCOUNT));
		
		assertEquals(3, prompt.size());
	}
}
