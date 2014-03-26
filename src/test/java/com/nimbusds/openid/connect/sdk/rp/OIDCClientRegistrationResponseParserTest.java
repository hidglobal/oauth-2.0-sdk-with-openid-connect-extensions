package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;

import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import junit.framework.TestCase;


/**
 * Tests the OIDC client registration response parser.
 */
public class OIDCClientRegistrationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		ClientID id = new ClientID("123");
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/cb"));
		metadata.setName("My app");
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(id, regURI, accessToken, metadata, null, null);

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo);

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		response = (OIDCClientInformationResponse)regResponse;

		assertEquals(id, response.getOIDCClientInformation().getID());
		assertEquals(regURI, response.getOIDCClientInformation().getRegistrationURI());
		assertEquals(accessToken.getValue(), response.getOIDCClientInformation().getRegistrationAccessToken().getValue());
		assertEquals("My app", response.getOIDCClientInformation().getClientMetadata().getName());
		assertNull(response.getOIDCClientInformation().getSecret());
		assertNull(response.getOIDCClientInformation().getIssueDate());
	}


	public void testParseError()
		throws Exception {

		ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(BearerTokenError.INVALID_TOKEN);

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		response = (ClientRegistrationErrorResponse)regResponse;
		assertEquals(BearerTokenError.INVALID_TOKEN.getCode(), response.getErrorObject().getCode());
	}
}
