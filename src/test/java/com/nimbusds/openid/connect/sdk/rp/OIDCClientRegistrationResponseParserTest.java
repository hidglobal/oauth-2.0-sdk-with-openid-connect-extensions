package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * Tests the OIDC client registration response parser.
 */
public class OIDCClientRegistrationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		ClientID id = new ClientID("123");
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/cb"));
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();
		metadata.setName("My app");
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(id, null, metadata, null, regURI, accessToken);

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo);

		assertTrue(response.indicatesSuccess());

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		assertTrue(regResponse.indicatesSuccess());
		response = (OIDCClientInformationResponse)regResponse;

		assertEquals(id, response.getOIDCClientInformation().getID());
		assertEquals("My app", response.getOIDCClientInformation().getMetadata().getName());
		assertNull(response.getOIDCClientInformation().getSecret());
		assertNull(response.getOIDCClientInformation().getIDIssueDate());
		assertEquals(regURI, response.getOIDCClientInformation().getRegistrationURI());
		assertEquals(accessToken.getValue(), response.getOIDCClientInformation().getRegistrationAccessToken().getValue());
	}


	public void testParseError()
		throws Exception {

		ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(BearerTokenError.INVALID_TOKEN);
		assertFalse(response.indicatesSuccess());

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		assertFalse(regResponse.indicatesSuccess());
		response = (ClientRegistrationErrorResponse)regResponse;
		assertEquals(BearerTokenError.INVALID_TOKEN.getCode(), response.getErrorObject().getCode());
	}
}
