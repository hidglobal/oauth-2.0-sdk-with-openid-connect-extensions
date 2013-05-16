package com.nimbusds.openid.connect.sdk.op;


import junit.framework.TestCase;


/**
 * Tests the OpenID Connect provider configuration class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ProviderConfigurationTest extends TestCase {


	private static final String CONFIG = "{" +
		"\"version\":\"3.0\"," +
		"\"authorization_endpoint\":\"https://server.example.com/connect/authorize\"," + 
		"\"issuer\":\"https://server.example.com\"," + 
		"\"token_endpoint\":\"https://server.example.com/connect/token\"," + 
		"\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\", \"private_key_jwt\"]," + 
		"\"token_endpoint_alg_values_supported\":[\"RS256\", \"ES256\"]," + 
		"\"userinfo_endpoint\":\"https://server.example.com/connect/userinfo\"," + 
		"\"check_session_iframe\":\"https://server.example.com/connect/check_session\"," + 
		"\"end_session_endpoint\":\"https://server.example.com/connect/end_session\"," + 
		"\"jwk_url\":\"https://server.example.com/jwks.json\"," + 
		"\"x509_url\":\"https://server.example.com/x509.pem\"," + 
		"\"registration_endpoint\":\"https://server.example.com/connect/register\"," + 
		"\"scopes_supported\":[\"openid\", \"profile\", \"email\", \"address\", \"phone\", \"offline_access\"]," + 
		"\"response_types_supported\":[\"code\", \"code id_token\", \"id_token\", \"token id_token\"]," + 
		"\"acr_values_supported\":[\"1\",\"2\",\"http://id.incommon.org/assurance/bronze\"]," + 
		"\"subject_types_supported\":[\"public\", \"pairwise\"]," + 
		"\"userinfo_signing_alg_values_supported\":[\"RS256\", \"ES256\", \"HS256\"]," + 
		"\"userinfo_encryption_alg_values_supported\":[\"RSA1_5\", \"A128KW\"]," + 
		"\"userinfo_encryption_enc_values_supported\":[\"A128CBC+HS256\", \"A128GCM\"]," + 
		"\"id_token_signing_alg_values_supported\":[\"RS256\", \"ES256\", \"HS256\"]," + 
		"\"id_token_encryption_alg_values_supported\":[\"RSA1_5\", \"A128KW\"]," + 
		"\"id_token_encryption_enc_values_supported\":[\"A128CBC+HS256\", \"A128GCM\"]," + 
		"\"request_object_signing_alg_values_supported\":[\"none\", \"RS256\", \"ES256\"]," + 
		"\"display_values_supported\":[\"page\", \"popup\"]," + 
		"\"claim_types_supported\":[\"normal\", \"distributed\"]," + 
		"\"claims_supported\":[\"sub\", \"iss\", \"auth_time\", \"acr\"," + 
		"\"name\", \"given_name\", \"family_name\", \"nickname\",\"profile\", \"picture\", \"website\",\"email\", \"email_verified\", \"locale\", \"zoneinfo\"]," + 
		"\"service_documentation\":\"http://server.example.com/connect/service_documentation.html\"" + 
		"}";


	public void testParse()
		throws Exception {

		ProviderConfiguration config = ProviderConfiguration.parse(CONFIG);
	}
}