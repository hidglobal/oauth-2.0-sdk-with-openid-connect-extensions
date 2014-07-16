package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.net.URISyntaxException;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientUpdateRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect client registration request.
 * 
 * <p>Note that the update operation is not specified in OpenID Connect Dynamic
 * Client Registration.
 * 
 * <p>Example HTTP request:
 *
 * <pre>
 * PUT /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 *
 * {
 *  "client_id"                  :"s6BhdRkqt3",
 *  "client_secret"              : "cf136dc3c1fc93f31185e5885805d",
 *  "redirect_uris"              : ["https://client.example.org/callback", "https://client.example.org/alt"],
 *  "scope"                      : "read write dolphin",
 *  "grant_types"                : ["authorization_code", "refresh_token"]
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 *  "client_name"                : "My New Example",
 *  "client_name#fr"             : "Mon Nouvel Exemple",
 *  "logo_uri"                   : "https://client.example.org/newlogo.png"
 *  "logo_uri#fr"                : "https://client.example.org/fr/newlogo.png"
 * }
 *
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol
 *         (draft-ietf-oauth-dyn-reg-management-01), section 2.3.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol
 *         (draft-ietf-oauth-dyn-reg-18), section 2.
 * </ul>
 */
@Immutable
public class OIDCClientUpdateRequest extends ClientUpdateRequest {
	
	
	/**
	 * Creates a new OpenID Connect client update request.
	 *
	 * @param uri         The URI of the client update endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest()}
	 *                    method will not be used.
	 * @param accessToken The client registration access token. Must not be
	 *                    {@code null}.
	 * @param metadata    The client metadata. Must not be {@code null} and 
	 *                    must specify one or more redirection URIs.
	 * @param secret      The optional client secret, {@code null} if not
	 *                    specified.
	 */
	public OIDCClientUpdateRequest(final URI uri,
		                       final ClientID id,
		                       final BearerAccessToken accessToken,
				       final OIDCClientMetadata metadata,
				       final Secret secret) {
		
		super(uri, id, accessToken, metadata, secret);
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
	 * Parses an OpenID Connect client update request from the specified 
	 * HTTP PUT request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The OpenID Connect client update request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        OpenID Connect client update request.
	 */
	public static OIDCClientUpdateRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.PUT);
		
		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest.getAuthorization());
		
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		
		ClientID id = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));

		OIDCClientMetadata metadata = OIDCClientMetadata.parse(jsonObject);
		
		Secret clientSecret = null;
		
		if (jsonObject.get("client_secret") != null)
			clientSecret = new Secret(JSONObjectUtils.getString(jsonObject, "client_secret"));


		URI endpointURI;

		try {
			endpointURI = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}
		
		return new OIDCClientUpdateRequest(endpointURI, id, accessToken, metadata, clientSecret);
	}
}
