package com.nimbusds.oauth2.sdk.auth;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests client secret basic authentication.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
public class ClientSecretBasicTest extends TestCase {


	public void testSerializeAndParse() {
	
		final String id = "Aladdin";
		final String pw = "open sesame";
		
		ClientID clientID = new ClientID(id);
		
		ClientSecretBasic csb = new ClientSecretBasic(clientID, pw);
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, csb.getMethod());
		
		assertEquals(id, csb.getClientID().toString());
		assertEquals(pw, csb.getClientSecret());
		
		String header = csb.toHTTPAuthorizationHeader();
		
		assertEquals("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", header);
		
		try {
			csb = ClientSecretBasic.parse(header);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(id, csb.getClientID().toString());
		assertEquals(pw, csb.getClientSecret());
	}
}
