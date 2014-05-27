package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.util.Date;
import java.util.Set;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


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


	public void testMinimalConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");

		ClientInformation info = new ClientInformation(clientID, null, metadata, null);

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals(metadata, info.getClientMetadata());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		String json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		Date now = new Date(new Date().getTime() / 1000 * 1000);
		Secret secret = new Secret("secret");

		info = new ClientInformation(clientID, now, metadata, secret);

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals(metadata, info.getClientMetadata());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());
	}


	public void testFullConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");

		ClientInformation info = new ClientInformation(clientID, null, metadata, null, null, null);

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals(metadata, info.getClientMetadata());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		String json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		Date now = new Date(new Date().getTime() / 1000 * 1000);
		Secret secret = new Secret("secret");
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		info = new ClientInformation(clientID, now, metadata, secret, regURI, accessToken);

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals(metadata, info.getClientMetadata());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());

		json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals("Example app", info.getClientMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());
	}
}
