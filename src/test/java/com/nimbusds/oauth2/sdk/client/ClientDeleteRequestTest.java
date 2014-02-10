package com.nimbusds.oauth2.sdk.client;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * Tests the client delete request.
 */
public class ClientDeleteRequestTest extends TestCase {


	public void testParseWithMissingAuthorizationHeader()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.DELETE, new URL("https://c2id.com/client-reg/123"));

		try {
			ClientDeleteRequest.parse(httpRequest);

			fail();

		} catch (ParseException e) {

			assertTrue(e.getErrorObject() instanceof BearerTokenError);

			BearerTokenError bte = (BearerTokenError)e.getErrorObject();

			assertEquals(401, bte.getHTTPStatusCode());
			assertNull(bte.getCode());
			assertEquals("Bearer", bte.toWWWAuthenticateHeader());
		}
	}
}
