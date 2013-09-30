package com.nimbusds.oauth2.sdk;


import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;


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


	public void testContains() {

		List<ResponseType> rtList = new ArrayList<ResponseType>();

		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);

		ResponseType rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);

		assertEquals(2, rtList.size());

		rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);
		assertTrue(rtList.contains(rt1));

		rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);
		assertTrue(rtList.contains(rt2));

		ResponseType rt3 = new ResponseType();
		rt3.add(OIDCResponseTypeValue.ID_TOKEN);

		assertFalse(rtList.contains(rt3));
	}
}
