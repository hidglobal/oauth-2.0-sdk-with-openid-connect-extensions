package com.nimbusds.oauth2.sdk.client;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests the client read request.
 */
public class ClientReadRequestTest extends TestCase {


	public void testCycle()
		throws Exception {

		URL url = new URL("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();

		ClientReadRequest request = new ClientReadRequest(url, accessToken);

		assertEquals(url, request.getEndpointURI());
		assertEquals(accessToken, request.getAccessToken());

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals(url, httpRequest.getURL());
		assertEquals(accessToken.toAuthorizationHeader(), httpRequest.getAuthorization());

		request = ClientReadRequest.parse(httpRequest);

		assertEquals(url.toString(), request.getEndpointURI().toString());
		assertEquals(accessToken.getValue(), request.getAccessToken().getValue());
	}
}
