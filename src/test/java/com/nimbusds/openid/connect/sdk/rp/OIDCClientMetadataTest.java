package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.net.URL;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * Tests the OIDC client metadata class.
 */
public class OIDCClientMetadataTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = OIDCClientMetadata.getRegisteredParameterNames();

		// Base OAuth 2.0 params
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
		assertTrue(paramNames.contains("request_object_encryption_alg"));
		assertTrue(paramNames.contains("request_object_encryption_enc"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg"));
		assertTrue(paramNames.contains("default_max_age"));
		assertTrue(paramNames.contains("require_auth_time"));
		assertTrue(paramNames.contains("default_acr_values"));
		assertTrue(paramNames.contains("initiate_login_uri"));
		assertTrue(paramNames.contains("request_uris"));
		assertTrue(paramNames.contains("post_logout_redirect_uris"));

		assertEquals(34, OIDCClientMetadata.getRegisteredParameterNames().size());
	}
	
	
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
		
		Set<URI> redirectURIs = clientMetadata.getRedirectionURIs();
		
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example", clientMetadata.getName());
		assertEquals("クライアント名", clientMetadata.getName(LangTag.parse("ja-Jpan-JP")));

		assertEquals(new URL("https://client.example.org/logo.png").toString(), clientMetadata.getLogoURI().toString());
		
		assertEquals(SubjectType.PAIRWISE, clientMetadata.getSubjectType());
		
		assertEquals(new URL("https://other.example.net/file_of_redirect_uris.json").toString(), clientMetadata.getSectorIDURI().toString());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientMetadata.getTokenEndpointAuthMethod());
		
		assertEquals(new URL("https://client.example.org/my_public_keys.jwks").toString(), clientMetadata.getJWKSetURI().toString());
		
		assertEquals(JWEAlgorithm.RSA1_5, clientMetadata.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, clientMetadata.getUserInfoJWEEnc());
		
		List<InternetAddress> contacts = clientMetadata.getContacts();
		
		assertTrue(new InternetAddress("ve7jtb@example.org").equals(contacts.get(0)));
		assertTrue(new InternetAddress("mary@example.org").equals(contacts.get(1)));
		assertEquals(2, contacts.size());
		
		Set<URI> requestURIs = clientMetadata.getRequestObjectURIs();
		
		assertTrue(requestURIs.contains(new URI("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")));
		assertEquals(1, requestURIs.size());

		assertTrue(clientMetadata.getCustomFields().isEmpty());
	}


	public void testGettersAndSetters()
		throws Exception {

		OIDCClientMetadata meta = new OIDCClientMetadata();

		assertNull(meta.getApplicationType());
		meta.setApplicationType(ApplicationType.NATIVE);
		assertEquals(ApplicationType.NATIVE, meta.getApplicationType());

		assertNull(meta.getSubjectType());
		meta.setSubjectType(SubjectType.PAIRWISE);
		assertEquals(SubjectType.PAIRWISE, meta.getSubjectType());

		assertNull(meta.getSectorIDURI());
		URI sectorIDURI = new URI("http://sector.id");
		meta.setSectorIDURI(sectorIDURI);
		assertEquals(sectorIDURI.toString(), meta.getSectorIDURI().toString());

		assertNull(meta.getRequestObjectURIs());
		Set<URI> requestObjURIs = new HashSet<>();
		requestObjURIs.add(new URI("http://client.com/reqobj"));
		meta.setRequestObjectURIs(requestObjURIs);
		assertEquals("http://client.com/reqobj", meta.getRequestObjectURIs().iterator().next().toString());
		assertEquals(1, meta.getRequestObjectURIs().size());

		assertNull(meta.getRequestObjectJWSAlg());
		meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());

		assertNull(meta.getRequestObjectJWEAlg());
		meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());

		assertNull(meta.getRequestObjectJWEEnc());
		meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());

		assertNull(meta.getTokenEndpointAuthJWSAlg());
		meta.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS384);
		assertEquals(JWSAlgorithm.HS384, meta.getTokenEndpointAuthJWSAlg());

		assertNull(meta.getIDTokenJWSAlg());
		meta.setIDTokenJWSAlg(JWSAlgorithm.PS256);
		assertEquals(JWSAlgorithm.PS256, meta.getIDTokenJWSAlg());

		assertNull(meta.getIDTokenJWEAlg());
		meta.setIDTokenJWEAlg(JWEAlgorithm.A128KW);
		assertEquals(JWEAlgorithm.A128KW, meta.getIDTokenJWEAlg());

		assertNull(meta.getIDTokenJWEEnc());
		meta.setIDTokenJWEEnc(EncryptionMethod.A128GCM);
		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEnc());

		assertNull(meta.getUserInfoJWSAlg());
		meta.setUserInfoJWSAlg(JWSAlgorithm.ES256);
		assertEquals(JWSAlgorithm.ES256, meta.getUserInfoJWSAlg());

		assertNull(meta.getUserInfoJWEAlg());
		meta.setUserInfoJWEAlg(JWEAlgorithm.ECDH_ES);
		assertEquals(JWEAlgorithm.ECDH_ES, meta.getUserInfoJWEAlg());

		assertNull(meta.getUserInfoJWEEnc());
		meta.setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEnc());

		assertEquals(0, meta.getDefaultMaxAge());
		meta.setDefaultMaxAge(3600);
		assertEquals(3600, meta.getDefaultMaxAge());

		assertFalse(meta.requiresAuthTime());
		meta.requiresAuthTime(true);
		assertTrue(meta.requiresAuthTime());

		assertNull(meta.getDefaultACRs());
		List<ACR> acrList = new LinkedList<>();
		acrList.add(new ACR("1"));
		meta.setDefaultACRs(acrList);
		assertEquals("1", meta.getDefaultACRs().get(0).toString());

		assertNull(meta.getInitiateLoginURI());
		meta.setInitiateLoginURI(new URI("http://do-login.com"));
		assertEquals("http://do-login.com", meta.getInitiateLoginURI().toString());

		assertNull(meta.getPostLogoutRedirectionURIs());
		Set<URI> logoutURIs = new HashSet<>();
		logoutURIs.add(new URI("http://post-logout.com"));
		meta.setPostLogoutRedirectionURIs(logoutURIs);
		assertEquals("http://post-logout.com", meta.getPostLogoutRedirectionURIs().iterator().next().toString());

		String json = meta.toJSONObject().toJSONString();

		meta = OIDCClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(ApplicationType.NATIVE, meta.getApplicationType());

		assertEquals(SubjectType.PAIRWISE, meta.getSubjectType());

		assertEquals(sectorIDURI.toString(), meta.getSectorIDURI().toString());

		assertEquals("http://client.com/reqobj", meta.getRequestObjectURIs().iterator().next().toString());
		assertEquals(1, meta.getRequestObjectURIs().size());

		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());

		assertEquals(JWSAlgorithm.HS384, meta.getTokenEndpointAuthJWSAlg());
		assertEquals(JWSAlgorithm.PS256, meta.getIDTokenJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getIDTokenJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEnc());

		assertEquals(JWSAlgorithm.ES256, meta.getUserInfoJWSAlg());
		assertEquals(JWEAlgorithm.ECDH_ES, meta.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEnc());

		assertEquals(3600, meta.getDefaultMaxAge());

		assertTrue(meta.requiresAuthTime());

		assertEquals("1", meta.getDefaultACRs().get(0).toString());

		assertEquals("http://do-login.com", meta.getInitiateLoginURI().toString());

		assertEquals("http://post-logout.com", meta.getPostLogoutRedirectionURIs().iterator().next().toString());
	}


	public void testCustomFields()
		throws Exception {

		OIDCClientMetadata meta = new OIDCClientMetadata();

		meta.setCustomField("x-data", "123");

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String)meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());

		String json = meta.toJSONObject().toJSONString();

		meta = OIDCClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String)meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());
	}


	public void testApplyDefaults() {

		OIDCClientMetadata metadata = new OIDCClientMetadata();

		assertNull(metadata.getResponseTypes());
		assertNull(metadata.getGrantTypes());
		assertNull(metadata.getTokenEndpointAuthMethod());
		assertNull(metadata.getIDTokenJWSAlg());
		assertNull(metadata.getApplicationType());

		metadata.applyDefaults();

		assertTrue(metadata.getResponseTypes().contains(ResponseType.getDefault()));
		assertTrue(metadata.getResponseTypes().contains(new ResponseType(ResponseType.Value.CODE)));
		assertEquals(1, metadata.getResponseTypes().size());

		assertTrue(metadata.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
		assertEquals(1, metadata.getGrantTypes().size());

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());

		assertEquals(JWSAlgorithm.RS256, metadata.getIDTokenJWSAlg());

		assertEquals(ApplicationType.WEB, metadata.getApplicationType());
	}


	public void testSerialiseDefaultRequireAuthTime() {

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.applyDefaults();

		JSONObject jsonObject = metadata.toJSONObject();

		assertNull(jsonObject.get("require_auth_time"));
	}


	public void testSerialiseNonDefaultRequireAuthTime() {

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.requiresAuthTime(true);
		metadata.applyDefaults();

		JSONObject jsonObject = metadata.toJSONObject();

		assertTrue((Boolean) jsonObject.get("require_auth_time"));
	}


	public void testJOSEAlgEquality()
		throws Exception {

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.applyDefaults();

		metadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
		metadata.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setIDTokenJWEEnc(EncryptionMethod.A128GCM);

		metadata.setUserInfoJWSAlg(JWSAlgorithm.RS256);
		metadata.setUserInfoJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setUserInfoJWEEnc(EncryptionMethod.A128GCM);

		metadata.setRequestObjectJWSAlg(JWSAlgorithm.HS256);
		metadata.setRequestObjectJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);

		metadata = OIDCClientMetadata.parse(JSONObjectUtils.parseJSONObject(metadata.toJSONObject().toJSONString()));

		assertEquals(JWSAlgorithm.RS256, metadata.getIDTokenJWSAlg());
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getIDTokenJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, metadata.getIDTokenJWEEnc());

		assertEquals(JWSAlgorithm.RS256, metadata.getUserInfoJWSAlg());
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, metadata.getIDTokenJWEEnc());

		assertEquals(JWSAlgorithm.HS256, metadata.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, metadata.getRequestObjectJWEEnc());
	}


	public void testJOSEEncMethodParseWithCEKCheck()
		throws Exception {

		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issue/127/oidcclient-parse-method-causes-potential

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.applyDefaults();

		metadata.setIDTokenJWEEnc(EncryptionMethod.A128GCM);
		metadata.setUserInfoJWEEnc(EncryptionMethod.A128GCM);
		metadata.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);

		metadata = OIDCClientMetadata.parse(JSONObjectUtils.parseJSONObject(metadata.toJSONObject().toJSONString()));

		assertEquals(128, metadata.getIDTokenJWEEnc().cekBitLength());
		assertEquals(128, metadata.getUserInfoJWEEnc().cekBitLength());
		assertEquals(256, metadata.getRequestObjectJWEEnc().cekBitLength());
	}
}