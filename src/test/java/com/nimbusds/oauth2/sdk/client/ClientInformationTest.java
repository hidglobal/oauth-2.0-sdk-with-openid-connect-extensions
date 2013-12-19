package com.nimbusds.oauth2.sdk.client;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.Set;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;


/**
 * Tests the client information class.
 */
public class ClientInformationTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = ClientInformation.getRegisteredParameterNames();

		assertTrue(paramNames.contains("client_id"));
		assertTrue(paramNames.contains("client_id_issued_at"));
		assertTrue(paramNames.contains("registration_access_token"));
		assertTrue(paramNames.contains("registration_client_uri"));
		assertTrue(paramNames.contains("client_secret"));
		assertTrue(paramNames.contains("client_secret_expires_at"));

		assertTrue(paramNames.contains("redirect_uris"));
		assertTrue(paramNames.contains("client_name"));
		assertTrue(paramNames.contains("client_uri"));
		assertTrue(paramNames.contains("logo_uri"));
		assertTrue(paramNames.contains("contacts"));
		assertTrue(paramNames.contains("tos_uri"));
		assertTrue(paramNames.contains("policy_uri"));
		assertTrue(paramNames.contains("token_endpoint_auth_method"));
		assertTrue(paramNames.contains("scope"));
		assertTrue(paramNames.contains("grant_types"));
		assertTrue(paramNames.contains("response_types"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("software_id"));
		assertTrue(paramNames.contains("software_version"));

		assertEquals(21, paramNames.size());
	}


	public void testConstructor()
		throws MalformedURLException {

		ClientID clientID = new ClientID("123");

		URL regURL = new URL("https://c2id.com/client-reg/123");

		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");

		Secret secret = new Secret("secret");

		Date now = new Date();

		ClientInformation info = new ClientInformation(clientID, regURL, accessToken, metadata, secret, now);

		assertEquals(clientID, info.getID());
		assertEquals(regURL, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());
		assertEquals(metadata, info.getClientMetadata());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(now, info.getIssueDate());
	}


	public void testSerializeAndParse()
		throws MalformedURLException, ParseException {

		ClientID clientID = new ClientID("123");

		URL regURL = new URL("https://c2id.com/client-reg/123");

		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");

		Secret secret = new Secret("secret");

		Date now = new Date(new Date().getTime() / 1000 * 1000);

		ClientInformation info = new ClientInformation(clientID, regURL, accessToken, metadata, secret, now);

		String json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(clientID, info.getID());
		assertEquals(regURL.toString(), info.getRegistrationURI().toString());
		assertEquals(accessToken.getValue(), info.getRegistrationAccessToken().getValue());
		assertEquals(metadata.getName(), info.getClientMetadata().getName());
		assertEquals(now.getTime(), info.getIssueDate().getTime());
	}
}
