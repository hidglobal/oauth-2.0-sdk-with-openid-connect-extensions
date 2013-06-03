package com.nimbusds.openid.connect.sdk;


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.net.URL;
import java.util.List;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;

import com.nimbusds.openid.connect.sdk.rp.ClientDetails;


/**
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCClientAddRequestTest extends TestCase {
	
	
	public void testParseSpecExample()
		throws Exception {
		
		URL regEndpoint = new URL("https://server.example.com//connect/register");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, regEndpoint);
		
		BearerAccessToken regToken = new BearerAccessToken("eyJhbGciOiJSUzI1NiJ9.eyJ");
		
		httpRequest.setAuthorization(regToken.toAuthorizationHeader());
		
		httpRequest.setContentType("application/json; charset=utf-8");
		
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

		httpRequest.setQuery(jsonString);
		
		OIDCClientRegisterRequest request = OIDCClientRegisterRequest.parse(httpRequest);
		
		ClientDetails client = request.getClientDetails();
		
		assertEquals(ApplicationType.WEB, client.getApplicationType());
		
		Set<URL> redirectURIs = client.getRedirectURIs();
		
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example", client.getName());
		assertEquals("クライアント名", client.getName(LangTag.parse("ja-Jpan-JP")));

		assertEquals(new URL("https://client.example.org/logo.png").toString(), client.getLogoURI().toString());
		
		assertEquals(SubjectType.PAIRWISE, client.getSubjectType());
		
		assertEquals(new URL("https://other.example.net/file_of_redirect_uris.json").toString(), client.getSectorIDURI().toString());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, client.getTokenEndpointAuthMethod());
		
		assertEquals(new URL("https://client.example.org/my_public_keys.jwks").toString(), client.getJWKSetURI().toString());
		
		assertEquals(JWEAlgorithm.RSA1_5, client.getUserInfoJWEAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, client.getUserInfoJWEEncryptionMethod());
		
		List<InternetAddress> contacts = client.getContacts();
		
		assertTrue(new InternetAddress("ve7jtb@example.org").equals(contacts.get(0)));
		assertTrue(new InternetAddress("mary@example.org").equals(contacts.get(1)));
		assertEquals(2, contacts.size());
		
		Set<URL> requestURIs = client.getRequestObjectURIs();
		
		assertTrue(requestURIs.contains(new URL("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")));
		assertEquals(1, requestURIs.size());
		
	}
}