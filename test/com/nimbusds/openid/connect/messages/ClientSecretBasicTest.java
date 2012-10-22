package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.ClientID;


/**
 * Tests client secret basic authentication.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-10)
 */
public class ClientSecretBasicTest extends TestCase {


	public void testSerializeAndParse() {
	
		final String id = "Aladdin";
		final String pw = "open sesame";
		
		ClientID clientID = new ClientID();
		clientID.setClaimValue(id);
		
		ClientSecretBasic csb = new ClientSecretBasic(clientID, pw);
		
		assertEquals(ClientAuthentication.Method.CLIENT_SECRET_BASIC, csb.getMethod());
		
		assertEquals(id, csb.getClientID().getClaimValue());
		assertEquals(pw, csb.getClientSecret());
		
		String header = csb.toHTTPAuthorizationHeader();
		
		assertEquals("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", header);
		
		try {
			csb = ClientSecretBasic.parse(header);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(id, csb.getClientID().getClaimValue());
		assertEquals(pw, csb.getClientSecret());
	}
}
