package com.nimbusds.oauth2.sdk;


import java.util.Iterator;
import junit.framework.TestCase;


/**
 * Tests the response type set class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ResponseTypeSetTest extends TestCase {


	public void testCodeFlowDetection() {

		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
		assertTrue(rts.impliesCodeFlow());
		assertFalse(rts.impliesImplicitFlow());
	}


	public void testImplicitFlowDetection() {

		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.TOKEN);
		assertTrue(rts.impliesImplicitFlow());
		assertFalse(rts.impliesCodeFlow());
	}


	public void testSerializeAndParse() {

		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
		rts.add(new ResponseType("id_token"));

		System.out.println("response_type: " + rts);

		try {
			rts = ResponseTypeSet.parse(rts.toString());

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertTrue(rts.contains(ResponseType.CODE));
		assertTrue(rts.contains(new ResponseType("id_token")));
		assertEquals(2, rts.size());
	}
	
	
	public void testOrder() {
		
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(new ResponseType("code"));
		rts.add(new ResponseType("id_token"));
		rts.add(new ResponseType("token"));
		
		Iterator<ResponseType> it = rts.iterator();
		
		assertEquals(ResponseType.CODE, it.next());
		assertTrue(new ResponseType("id_token").equals(it.next()));
		assertEquals(ResponseType.TOKEN, it.next());
		
		assertFalse(it.hasNext());
	}


	public void testParseNull() {

		try {
			ResponseTypeSet.parse(null);

			fail("Failed to raise exception");
		
		} catch (ParseException e) {

			// ok
		}
	}


	public void testParseEmptyString() {

		try {
			ResponseTypeSet.parse(" ");

			fail("Failed to raise exception");
		
		} catch (ParseException e) {

			// ok
		}
	}
}
