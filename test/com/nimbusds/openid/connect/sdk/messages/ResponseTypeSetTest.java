package com.nimbusds.openid.connect.sdk.messages;


import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Tests request type parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public class ResponseTypeSetTest extends TestCase {
	
	
	public void testConstantNames() {
	
		assertEquals("code", ResponseType.CODE.toString());
		assertEquals("id_token", ResponseType.ID_TOKEN.toString());
		assertEquals("token", ResponseType.TOKEN.toString());
	}
	
	
	public void testSerialization1() {
	
		ResponseTypeSet set = new ResponseTypeSet();
	
		set.add(ResponseType.CODE);
		set.add(ResponseType.ID_TOKEN);
		
		String out = set.toString();
		
		// order is important
		assertEquals("code id_token", out);
		
		assertTrue(set.impliesCodeFlow());
		assertFalse(set.impliesImplicitFlow());
	}
	
	
	public void testSerialization2() {
	
		ResponseTypeSet set = new ResponseTypeSet();
	
		set.add(ResponseType.CODE);
		set.add(ResponseType.TOKEN);
		
		String out = set.toString();
		
		// order is important
		assertEquals("code token", out);
		
		assertTrue(set.impliesCodeFlow());
		assertFalse(set.impliesImplicitFlow());
	}
	
	
	public void testSerialization3() {
	
		ResponseTypeSet set = new ResponseTypeSet();
	
		set.add(ResponseType.ID_TOKEN);
		set.add(ResponseType.TOKEN);
		
		String out = set.toString();
		
		// order is important
		assertEquals("token id_token", out);
		
		assertFalse(set.impliesCodeFlow());
		assertTrue(set.impliesImplicitFlow());
	}
	
	
	public void testSerialization4() {
	
		ResponseTypeSet set = new ResponseTypeSet();
	
		set.add(ResponseType.CODE);
		set.add(ResponseType.ID_TOKEN);
		set.add(ResponseType.TOKEN);
		
		String out = set.toString();
		
		// order is important
		assertEquals("code token id_token", out);
		
		assertTrue(set.impliesCodeFlow());
		assertFalse(set.impliesImplicitFlow());
	}
	
	
	public void testSetParsing1() {

		String in = "code id_token token";
		
		ResponseTypeSet set = null;
		
		try {
			set = ResponseTypeSet.parse(in);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
	
		assertTrue(set.contains(ResponseType.CODE));
		assertTrue(set.contains(ResponseType.ID_TOKEN));
		assertTrue(set.contains(ResponseType.TOKEN));
	}
	
	
	public void testSetParsing2() {

		String in = "id_token";
		
		ResponseTypeSet set = null;
		
		try {
			set = ResponseTypeSet.parse(in);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertTrue(set.contains(ResponseType.ID_TOKEN));
	}
	
	
	public void testSetParseException() {

		String in = "code id_token badtoken";
		
		ResponseTypeSet set = null;
		
		try {
			set = ResponseTypeSet.parse(in);
			
			fail("Failed to raise parse exception");
			
		} catch (ParseException e) {
		
			// ok
		}
	}
}
