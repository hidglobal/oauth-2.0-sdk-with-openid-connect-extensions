package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the response type class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ResponseTypeTest extends TestCase {
	
	
	public void testConstants() {

		assertEquals("code", ResponseType.Value.CODE.toString());
		assertEquals("token", ResponseType.Value.TOKEN.toString());
	}


	public void testCodeFlowDetection() {

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);
		assertTrue(rts.impliesCodeFlow());
		assertFalse(rts.impliesImplicitFlow());
	}


	public void testImplicitFlowDetection() {

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.TOKEN);
		assertTrue(rts.impliesImplicitFlow());
		assertFalse(rts.impliesCodeFlow());
	}


	public void testSerializeAndParse() {

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);
		rts.add(new ResponseType.Value("id_token"));

		System.out.println("response_type: " + rts);

		try {
			rts = ResponseType.parse(rts.toString());

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertTrue(rts.contains(ResponseType.Value.CODE));
		assertTrue(rts.contains(new ResponseType.Value("id_token")));
		assertEquals(2, rts.size());
	}


	public void testParseNull() {

		try {
			ResponseType.parse(null);

			fail("Failed to raise exception");
		
		} catch (ParseException e) {

			// ok
		}
	}


	public void testParseEmptyString() {

		try {
			ResponseType.parse(" ");

			fail("Failed to raise exception");
		
		} catch (ParseException e) {

			// ok
		}
	}
}
