package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import net.minidev.json.JSONObject;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * OpenID Connect client registration request. This class is immutable.
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
 *  "application_type"                : "web",
 *  "redirect_uris"                   : [ "https://client.example.org/callback",
 *                                        "https://client.example.org/callback2" ],
 *  "client_name"                     : "My Example",
 *  "client_name#ja-Jpan-JP"          : "クライアント名",
 *  "logo_uri"                        : "https://client.example.org/logo.png",
 *  "subject_type"                    : "pairwise",
 *  "sector_identifier_uri"           : "https://other.example.net/file_of_redirect_uris.json",
 *  "token_endpoint_auth_method"      : "client_secret_basic",
 *  "jwks_uri"                        : "https://client.example.org/my_public_keys.jwks",
 *  "userinfo_encrypted_response_alg" : "RSA1_5",
 *  "userinfo_encrypted_response_enc" : "A128CBC-HS256",
 *  "contacts"                        : [ "ve7jtb@example.org", "mary@example.org" ],
 *  "request_uris"                    : [ "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA" ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 3.1.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-14), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class OIDCClientRegistrationRequest extends ClientRegistrationRequest {
	
	
	/**
	 * Creates a new OpenID Connect client registration request.
	 *
	 * @param uri         The URI of the client registration endpoint. May 
	 *                    be {@code null} if the {@link #toHTTPRequest()}
	 *                    method will not be used.
	 * @param metadata    The OpenID Connect client metadata. Must not be 
	 *                    {@code null} and must specify one or more redirect 
	 *                    URIs.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public OIDCClientRegistrationRequest(final URL uri,
		                             final OIDCClientMetadata metadata, 
		                             final BearerAccessToken accessToken) {

		super(uri, metadata, accessToken);
	}
	
	
	/**
	 * Gets the associated OpenID Connect client metadata.
	 *
	 * @return The OpenID Connect client metadata.
	 */
	public OIDCClientMetadata getOIDCClientMetadata() {
		
		return (OIDCClientMetadata)getClientMetadata();
	}
	
	
	/**
	 * Parses an OpenID Connect client registration request from the 
	 * specified HTTP POST request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The OpenID Connect client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        OpenID Connect client registration request.
	 */
	public static OIDCClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.POST);

		// Parse the client metadata
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		OIDCClientMetadata metadata = OIDCClientMetadata.parse(jsonObject);

		// Parse the optional bearer access token
		BearerAccessToken accessToken = null;
		
		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isNotBlank(authzHeaderValue))
			accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		return new OIDCClientRegistrationRequest(httpRequest.getURL(), metadata, accessToken);
	}
}
