package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPRequest;


/**
 * Tests UserInfo request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-22)
 */
public class UserInfoRequestTest extends TestCase {
	
	
	public void testParseAndSerialize() {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET);
		AccessToken accessToken = new AccessToken("eyJhbGciOiJIUzI1NiJ9");
		httpRequest.setAuthorization(accessToken.toAuthorizationHeader());
		
		final String query = "schema=openid";
		httpRequest.setQuery(query);
		
		UserInfoRequest uir = null;
		
		try {
			uir = UserInfoRequest.parse(httpRequest);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPRequest.Method.GET, uir.getMethod());
		assertEquals("eyJhbGciOiJIUzI1NiJ9", uir.getAccessToken().getValue());
		
		try {
			httpRequest = uir.toHTTPRequest();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
	
		try {
			accessToken = AccessToken.parse(httpRequest.getAuthorization());
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("eyJhbGciOiJIUzI1NiJ9", accessToken.getValue());
		
		assertEquals("schema=openid", httpRequest.getQuery());
	}
}
