package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;


/**
 * Tests the prompt class.
 * 
 * @author Vladimir Dzhuvinov
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
	
	
	public void testListSerializationAndParsing()
		throws Exception {
		
		Prompt p = new Prompt();
		p.add(Prompt.Type.CONSENT);
		p.add(Prompt.Type.LOGIN);
		
		assertTrue(p.isValid());
		
		List<String> list = p.toList();
		
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
