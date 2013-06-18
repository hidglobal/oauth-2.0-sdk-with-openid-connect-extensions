package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;
import java.util.List;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.util.JSONObjectUtils;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.SubjectType;


/**
 * Tests the OIDC client metadata class.
 * 
 * @author Vladimir Dzhuvinov
 */
public class OIDCClientMetadataTest extends TestCase {
	
	
	public void testParseSpecExample()
		throws Exception {
		
		String jsonString = "{"
			+ "   \"application_type\": \"web\","
			+ "   \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/callback2\"],"
			+ "   \"client_name\": \"My Example\","
			+ "   \"client_name#ja-Jpan-JP\":\"クライアント名\","
			+ "   \"logo_uri\": \"https://client.example.org/logo.png\","
			+ "   \"subject_type\": \"pairwise\","
			+ "   \"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\","
			+ "   \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "   \"userinfo_encrypted_response_alg\": \"RSA1_5\","
			+ "   \"userinfo_encrypted_response_enc\": \"A128CBC-HS256\","
			+ "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],"
			+ "   \"request_uris\":[\"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA\"]"
			+ "  }";

		
		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(jsonString);
		
		OIDCClientMetadata clientMetadata = OIDCClientMetadata.parse(jsonObject);
		
		assertEquals(ApplicationType.WEB, clientMetadata.getApplicationType());
		
		Set<URL> redirectURIs = clientMetadata.getRedirectURIs();
		
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example", clientMetadata.getName());
		assertEquals("クライアント名", clientMetadata.getName(LangTag.parse("ja-Jpan-JP")));

		assertEquals(new URL("https://client.example.org/logo.png").toString(), clientMetadata.getLogoURI().toString());
		
		assertEquals(SubjectType.PAIRWISE, clientMetadata.getSubjectType());
		
		assertEquals(new URL("https://other.example.net/file_of_redirect_uris.json").toString(), clientMetadata.getSectorIDURI().toString());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientMetadata.getTokenEndpointAuthMethod());
		
		assertEquals(new URL("https://client.example.org/my_public_keys.jwks").toString(), clientMetadata.getJWKSetURI().toString());
		
		assertEquals(JWEAlgorithm.RSA1_5, clientMetadata.getUserInfoJWEAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, clientMetadata.getUserInfoJWEEncryptionMethod());
		
		List<InternetAddress> contacts = clientMetadata.getContacts();
		
		assertTrue(new InternetAddress("ve7jtb@example.org").equals(contacts.get(0)));
		assertTrue(new InternetAddress("mary@example.org").equals(contacts.get(1)));
		assertEquals(2, contacts.size());
		
		Set<URL> requestURIs = clientMetadata.getRequestObjectURIs();
		
		assertTrue(requestURIs.contains(new URL("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")));
		assertEquals(1, requestURIs.size());
	}
}