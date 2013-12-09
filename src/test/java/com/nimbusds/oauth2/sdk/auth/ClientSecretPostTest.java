package com.nimbusds.oauth2.sdk.auth;


import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests client secret basic authentication.
 */
public class ClientSecretPostTest extends TestCase {


	public void testSerializeAndParse()
		throws ParseException {

		// Test vectors from OAuth 2.0 RFC

		final String id = "s6BhdRkqt3";
		final String pw = "7Fjfp0ZBr1KtDRbnfVdmIw";

		ClientID clientID = new ClientID(id);
		Secret secret = new Secret(pw);

		ClientSecretPost csp = new ClientSecretPost(clientID, secret);

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, csp.getMethod());

		assertEquals(id, csp.getClientID().getValue());
		assertEquals(pw, csp.getClientSecret().getValue());

		Map<String,String> params = csp.toParameters();

		assertEquals(id, params.get("client_id"));
		assertEquals(pw, params.get("client_secret"));
		assertEquals(2, params.size());

		csp = ClientSecretPost.parse(params);

		assertEquals(id, csp.getClientID().toString());
		assertEquals(pw, csp.getClientSecret().getValue());
	}
}
