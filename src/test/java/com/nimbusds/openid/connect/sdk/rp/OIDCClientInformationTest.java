package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.util.Date;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Tests the OpenID Connect client information class.
 */
public class OIDCClientInformationTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = OIDCClientInformation.getRegisteredParameterNames();

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

		// OIDC specifid params
		assertTrue(paramNames.contains("application_type"));
		assertTrue(paramNames.contains("sector_identifier_uri"));
		assertTrue(paramNames.contains("subject_type"));
		assertTrue(paramNames.contains("id_token_signed_response_alg"));
		assertTrue(paramNames.contains("id_token_encrypted_response_alg"));
		assertTrue(paramNames.contains("id_token_encrypted_response_enc"));
		assertTrue(paramNames.contains("userinfo_signed_response_alg"));
		assertTrue(paramNames.contains("userinfo_encrypted_response_alg"));
		assertTrue(paramNames.contains("userinfo_encrypted_response_enc"));
		assertTrue(paramNames.contains("request_object_signing_alg"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg"));
		assertTrue(paramNames.contains("default_max_age"));
		assertTrue(paramNames.contains("require_auth_time"));
		assertTrue(paramNames.contains("default_acr_values"));
		assertTrue(paramNames.contains("initiate_login_uri"));
		assertTrue(paramNames.contains("request_uris"));
		assertTrue(paramNames.contains("post_logout_redirect_uris"));

		assertEquals(40, paramNames.size());
	}


	public void testConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		Date now = new Date(new Date().getTime() / 1000 * 1000);
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setName("Example app");
		Secret secret = new Secret("secret");
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		OIDCClientInformation info = new OIDCClientInformation(clientID, now, metadata, secret, regURI, accessToken);

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals(metadata, info.getOIDCMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());

		String json = info.toJSONObject().toJSONString();

		info = OIDCClientInformation.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals("Example app", info.getOIDCMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());
	}
}
