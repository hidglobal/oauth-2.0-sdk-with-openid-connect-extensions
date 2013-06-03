package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import com.nimbusds.openid.connect.sdk.rp.ClientDetails;


/**
 * OpenID Connect client register request. This class is immutable.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /connect/register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
 *
 * {
 * "application_type"                : "web",
 * "redirect_uris"                   : [ "https://client.example.org/callback",
 *                                       "https://client.example.org/callback2" ],
 * "client_name"                     : "My Example",
 * "client_name#ja-Jpan-JP"          : "クライアント名",
 * "logo_uri"                        : "https://client.example.org/logo.png",
 * "subject_type"                    : "pairwise",
 * "sector_identifier_uri"           : "https://other.example.net/file_of_redirect_uris.json",
 * "token_endpoint_auth_method"      : "client_secret_basic",
 * "jwks_uri"                        : "https://client.example.org/my_public_keys.jwks",
 * "userinfo_encrypted_response_alg" : "RSA1_5",
 * "userinfo_encrypted_response_enc" : "A128CBC-HS256",
 * "contacts"                        : [ "ve7jtb@example.org", "mary@example.org" ],
 * "request_uris"                    : [ "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA" ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic ClientDetails Registration 1.0, section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class OIDCClientRegisterRequest extends ProtectedResourceRequest {


	/**
	 * The client details.
	 */
	private final ClientDetails client;


	/**
	 * Creates a new OpenID Connect client register request.
	 *
	 * @param client      The client details. Must not be {@code null} and 
	 *                    must specify one or more redirect URIs.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public OIDCClientRegisterRequest(final ClientDetails client, final BearerAccessToken accessToken) {

		super(accessToken);

		if (client.getRedirectURIs() == null || client.getRedirectURIs().isEmpty())
			throw new IllegalArgumentException("The client details must specify one or more redirect URIs");

		this.client = client;
	}


	/**
	 * Gets the associated client details.
	 *
	 * @return The client details.
	 */
	public ClientDetails getClientDetails() {

		return client;
	}


	@Override
	public HTTPRequest toHTTPRequest(final URL url) {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);

		if (getAccessToken() != null)
			httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery(client.toJSONObject().toString());

		return httpRequest;
	}


	/**
	 * Parses an OpenID Connect client register request from the
	 * specified HTTP POST request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client add (register) request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client register request.
	 */
	public static OIDCClientRegisterRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.POST);

		// Parse the client metadata
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		ClientDetails client = ClientDetails.parse(jsonObject);

		if (client.getRedirectURIs() == null || client.getRedirectURIs().isEmpty())
			throw new ParseException("The client details must specify one or more redirect URIs");

		// Parse the optinal bearer access token
		BearerAccessToken accessToken = null;
		
		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isNotBlank(authzHeaderValue))
			accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		return new OIDCClientRegisterRequest(client, accessToken);
	}
}