package com.nimbusds.oauth2.sdk.client;


import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * Tests the client registration error response class.
 */
public class ClientRegistrationErrorResponseTest extends TestCase {


	public void testStdErrors() {

		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(RegistrationError.INVALID_REDIRECT_URI));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(RegistrationError.INVALID_CLIENT_METADATA));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(RegistrationError.INVALID_SOFTWARE_STATEMENT));
		assertTrue(ClientRegistrationErrorResponse.getStandardErrors().contains(RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT));

		assertEquals(8, ClientRegistrationErrorResponse.getStandardErrors().size());
	}


	public void testErrorObject() {

		ClientRegistrationErrorResponse errorResponse =
			new ClientRegistrationErrorResponse(RegistrationError.INVALID_REDIRECT_URI);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(RegistrationError.INVALID_REDIRECT_URI, errorResponse.getErrorObject());
	}


	public void testToHTTPResponse()
		throws Exception {

		HTTPResponse httpResponse =
			new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA).toHTTPResponse();

		assertEquals(400, httpResponse.getStatusCode());
		assertTrue(CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType()));
		JSONObject content = httpResponse.getContentAsJSONObject();
		assertEquals("invalid_client_metadata", (String)content.get("error"));
		assertEquals("Invalid client metadata field", (String)content.get("error_description"));

		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
	}


	public void testParse()
		throws Exception {

		HTTPResponse httpResponse =
			new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA).toHTTPResponse();

		ClientRegistrationErrorResponse errorResponse =
			ClientRegistrationErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(RegistrationError.INVALID_CLIENT_METADATA, errorResponse.getErrorObject());
	}


	public void testParse404NotFound()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(404);

		ClientRegistrationErrorResponse errorResponse =
			ClientRegistrationErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertTrue(errorResponse.getErrorObject().toJSONObject().isEmpty());
	}
}
