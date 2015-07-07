package com.nimbusds.oauth2.sdk.auth;


import java.nio.charset.Charset;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests client secret basic authentication.
 */
public class ClientSecretBasicTest extends TestCase {


	public void testSerializeAndParse()
		throws ParseException {
	
		// Test vectors from OAuth 2.0 RFC
		
		final String id = "s6BhdRkqt3";
		final String pw = "7Fjfp0ZBr1KtDRbnfVdmIw";
		
		ClientID clientID = new ClientID(id);
		Secret secret = new Secret(pw);
		
		ClientSecretBasic csb = new ClientSecretBasic(clientID, secret);
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, csb.getMethod());
		
		assertEquals(id, csb.getClientID().toString());
		assertEquals(pw, csb.getClientSecret().getValue());
		
		String header = csb.toHTTPAuthorizationHeader();
		
		assertEquals("Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3", header);
		
		csb = ClientSecretBasic.parse(header);
		
		assertEquals(id, csb.getClientID().toString());
		assertEquals(pw, csb.getClientSecret().getValue());
	}


	public void testParseAndSerialize()
		throws Exception {

		String header = "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3";

		ClientSecretBasic csb = ClientSecretBasic.parse(header);

		assertEquals("s6BhdRkqt3", csb.getClientID().getValue());
		assertEquals("7Fjfp0ZBr1KtDRbnfVdmIw", csb.getClientSecret().getValue());
	}


	public void testSecretWithBackslashes()
		throws Exception {

		final String id = "IX-1FXURP1U93W11";
		final String pw = "cXqXbCJTOUJfypCD92ZNNviQxvYitAN6vH0zF8h/nFy6+yH7ERVlPpIZnUqYfCzaHZYkziI7QBCK88juLTC/t9WwjiMi6WbecE3y+tnD2lniI6PK7n4jMTBhaJPNqfHpvdh13GZswc92HtPSLQYbiKxzgAPhnmFa/1hV+GfmnEp+IXnDRukHA8AaX6L3d4x6T608+2dZRnqOM4+DB7K4vFNm+3bYcEpHz5zhBAulXQMp+GziCoKRcWrQfjHx1cSsmh+R/F6BZLHkVvNF6XKaKA2sDlxc9Bx3EwfNFJYojWiGr+WTD8slrDw6yfbZKTYsfgYFCYf0gSUsV8mHIxaZQA==";

		ClientID clientID = new ClientID(id);
		Secret secret = new Secret(pw);

		ClientSecretBasic csb = new ClientSecretBasic(clientID, secret);

		String header = csb.toHTTPAuthorizationHeader();csb = ClientSecretBasic.parse(header);

		assertTrue(clientID.equals(csb.getClientID()));
		assertTrue(secret.equals(csb.getClientSecret()));

		assertEquals(id, csb.getClientID().getValue());
		assertEquals(pw, csb.getClientSecret().getValue());
	}


	public void testNonEscapedSecretWithLegacyBasicAuth()
		throws Exception {

		// Test legacy HTTP basic auth without HTTP URL escape of charc in username + password
		// See http://tools.ietf.org/html/rfc6749#section-2.3.1

		final String id = "IX-1FXURP1U93W11";
		final String pw = "cXqXbCJTOUJfypCD92ZNNviQxvYitAN6vH0zF8h\\/nFy6+yH7ERVlPpIZnUqYfCzaHZYkziI7QBCK88juLTC\\/t9WwjiMi6WbecE3y+tnD2lniI6PK7n4jMTBhaJPNqfHpvdh13GZswc92HtPSLQYbiKxzgAPhnmFa\\/1hV+GfmnEp+IXnDRukHA8AaX6L3d4x6T608+2dZRnqOM4+DB7K4vFNm+3bYcEpHz5zhBAulXQMp+GziCoKRcWrQfjHx1cSsmh+R\\/F6BZLHkVvNF6XKaKA2sDlxc9Bx3EwfNFJYojWiGr+WTD8slrDw6yfbZKTYsfgYFCYf0gSUsV8mHIxaZQA==";

		String credentials = id + ":" + pw;

		String header = "Basic " + Base64.encodeBase64String(credentials.getBytes(Charset.forName("UTF-8")));

		assertEquals(header,
			"Basic SVgtMUZYVVJQMVU5M1cxMTpjWHFYYkNKVE9VSmZ5cENEOTJaTk52aVF4dllpdEFONnZIMHpGOGhcL25GeTYreUg3RVJWbFBwSVpuVXFZZkN6YUhaWWt6aUk3UUJDSzg4anVMVENcL3Q5V3dqaU1pNldiZWNFM3krdG5EMmxuaUk2UEs3bjRqTVRCaGFKUE5xZkhwdmRoMTNHWnN3YzkySHRQU0xRWWJpS3h6Z0FQaG5tRmFcLzFoVitHZm1uRXArSVhuRFJ1a0hBOEFhWDZMM2Q0eDZUNjA4KzJkWlJucU9NNCtEQjdLNHZGTm0rM2JZY0VwSHo1emhCQXVsWFFNcCtHemlDb0tSY1dyUWZqSHgxY1NzbWgrUlwvRjZCWkxIa1Z2TkY2WEthS0Eyc0RseGM5QngzRXdmTkZKWW9qV2lHcitXVEQ4c2xyRHc2eWZiWktUWXNmZ1lGQ1lmMGdTVXNWOG1ISXhhWlFBPT0=");
	}


	public void testWithLegacyExample() {

		final String id = "Aladdin";
		final String pw = "open sesame";

		ClientSecretBasic cb = new ClientSecretBasic(new ClientID(id), new Secret(pw));

		// Must not match legacy example
		assertNotSame("QWxhZGRpbjpvcGVuIHNlc2FtZQ==", cb.toHTTPAuthorizationHeader());
	}
}
