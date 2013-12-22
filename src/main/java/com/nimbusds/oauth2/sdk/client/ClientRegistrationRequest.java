package com.nimbusds.oauth2.sdk.client;


import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Client registration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Authorization: Bearer ey23f2.adfj230.af32-developer321
 * Host: server.example.com
 *
 * {
 *  "redirect_uris"              : ["https://client.example.org/callback", 
 *                                  "https://client.example.org/callback2"],
 *  "client_name"                : "My Example Client",
 *  "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "scope"                      : "read write dolphin",
 *  "logo_uri"                   : "https://client.example.org/logo.png",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-14), section 3.1.
 * </ul>
 */
@Immutable
public class ClientRegistrationRequest extends ProtectedResourceRequest {


	/**
	 * The client metadata.
	 */
	private final ClientMetadata metadata;


	/**
	 * Creates a new client registration request.
	 *
	 * @param uri         The URI of the client registration endpoint. May 
	 *                    be {@code null} if the {@link #toHTTPRequest()}
	 *                    method will not be used.
	 * @param metadata    The client metadata. Must not be {@code null} and 
	 *                    must specify one or more redirect URIs.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public ClientRegistrationRequest(final URL uri,
		                         final ClientMetadata metadata, 
		                         final BearerAccessToken accessToken) {

		super(uri, accessToken);

		if (metadata == null)
			throw new IllegalArgumentException("The client metadata must not be null");
		
		this.metadata = metadata;
	}


	/**
	 * Gets the associated client metadata.
	 *
	 * @return The client metadata.
	 */
	public ClientMetadata getClientMetadata() {

		return metadata;
	}


	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException{
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());

		if (getAccessToken() != null)
			httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery(metadata.toJSONObject().toString());

		return httpRequest;
	}


	/**
	 * Parses a client registration request from the specified HTTP POST 
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client registration request.
	 */
	public static ClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.POST);

		// Parse the client metadata
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		ClientMetadata metadata = ClientMetadata.parse(jsonObject);

		// Parse the optional bearer access token
		BearerAccessToken accessToken = null;
		
		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isNotBlank(authzHeaderValue))
			accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		return new ClientRegistrationRequest(httpRequest.getURL(), metadata, accessToken);
	}
}