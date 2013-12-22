package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests the UserInfo request.
 */
public class UserInfoRequestTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {

		URL url = new URL("https://c2id.com/userinfo");
		BearerAccessToken token = new BearerAccessToken();

		UserInfoRequest request = new UserInfoRequest(url, token);

		assertEquals(url, request.getEndpointURI());
		assertEquals(token, request.getAccessToken());
		assertEquals(HTTPRequest.Method.GET, request.getMethod());

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals(url, httpRequest.getURL());
		assertNull(httpRequest.getQuery());
		assertEquals(token.toAuthorizationHeader(), httpRequest.getAuthorization());

		request = UserInfoRequest.parse(httpRequest);

		assertEquals(url, request.getEndpointURI());
		assertEquals(token, request.getAccessToken());
		assertEquals(HTTPRequest.Method.GET, request.getMethod());
	}


	public void testFullConstructor()
		throws Exception {

		URL url = new URL("https://c2id.com/userinfo");
		BearerAccessToken token = new BearerAccessToken();

		UserInfoRequest request = new UserInfoRequest(url, HTTPRequest.Method.POST, token);

		assertEquals(url, request.getEndpointURI());
		assertEquals(token, request.getAccessToken());
		assertEquals(HTTPRequest.Method.POST, request.getMethod());

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(url, httpRequest.getURL());
		assertEquals("application/x-www-form-urlencoded; charset=UTF-8", httpRequest.getContentType().toString());
		assertEquals("access_token="+token.getValue(), httpRequest.getQuery());
		assertNull(httpRequest.getAuthorization());

		request = UserInfoRequest.parse(httpRequest);

		assertEquals(url, request.getEndpointURI());
		assertEquals(token, request.getAccessToken());
		assertEquals(HTTPRequest.Method.POST, request.getMethod());
	}
}
