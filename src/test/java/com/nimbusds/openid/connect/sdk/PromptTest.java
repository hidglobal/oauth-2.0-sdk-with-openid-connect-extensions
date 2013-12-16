package com.nimbusds.openid.connect.sdk;


import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the prompt class.
 */
public class PromptTest extends TestCase {

	
	public void testRun()
		throws Exception {
		
		Prompt p = new Prompt();
		p.add(Prompt.Type.CONSENT);
		p.add(Prompt.Type.LOGIN);
		
		assertTrue(p.isValid());
		
		String s = p.toString();
		
		p = Prompt.parse(s);
		
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertEquals(2, p.size());
	}


	public void testVarargConstructor() {

		Prompt p = new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT, Prompt.Type.SELECT_ACCOUNT);

		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.SELECT_ACCOUNT));

		assertEquals(3, p.size());

		assertTrue(p.isValid());
	}


	public void testVarargStringConstructor() {

		Prompt p = new Prompt("login", "consent", "select_account");

		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.SELECT_ACCOUNT));

		assertEquals(3, p.size());

		assertTrue(p.isValid());
	}
	
	
	public void testListSerializationAndParsing()
		throws Exception {
		
		Prompt p = new Prompt();
		p.add(Prompt.Type.CONSENT);
		p.add(Prompt.Type.LOGIN);
		
		assertTrue(p.isValid());
		
		List<String> list = p.toStringList();
		
		assertTrue(list.contains("consent"));
		assertTrue(list.contains("login"));
		assertEquals(2, list.size());
		
		p = Prompt.parse(list);
		
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertEquals(2, p.size());
	}
	
	
	public void testParseInvalidPrompt() {
		
		try {
			Prompt.parse("none login");
			fail("Failed to raise exception on none login");
		} catch (ParseException ex) {
			// ok
		}
		
		try {
			Prompt.parse("none consent");
			fail("Failed to raise exception on none consent");
		} catch (ParseException ex) {
			// ok
		}
		
		try {
			Prompt.parse("none select_account");
			fail("Failed to raise exception on none select_account");
		} catch (ParseException ex) {
			// ok
		}
		
		try {
			Prompt.parse("none login consent select_account");
			fail("Failed to raise exception on none consent select_account");
		} catch (ParseException ex) {
			// ok
		}
	}
}
