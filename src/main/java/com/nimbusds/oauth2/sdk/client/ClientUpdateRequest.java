package com.nimbusds.oauth2.sdk.client;


import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Client registration request.
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
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-14), section 4.3.
 * </ul>
 */
@Immutable
public class ClientUpdateRequest extends ProtectedResourceRequest {
	
	
	/**
	 * The registered client ID.
	 */
	private final ClientID id;
	
	
	/**
	 * The client metadata.
	 */
	private final ClientMetadata metadata;
	
	
	/**
	 * The optional client secret.
	 */
	private final Secret secret;
	
	
	/**
	 * Creates a new client update request.
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
	public ClientUpdateRequest(final URL uri,
		                   final ClientID id,
		                   final BearerAccessToken accessToken,
				   final ClientMetadata metadata, 
				   final Secret secret) {

		super(uri, accessToken);
		
		if (id == null)
			throw new IllegalArgumentException("The client identifier must not be null");
		
		this.id = id;

		if (metadata == null)
			throw new IllegalArgumentException("The client metadata must not be null");
		
		this.metadata = metadata;
		
		this.secret = secret;
	}
	
	
	/**
	 * Gets the client ID. Corresponds to the {@code client_id} client
	 * registration parameter.
	 *
	 * @return The client ID, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return id;
	}
	
	
	/**
	 * Gets the associated client metadata.
	 *
	 * @return The client metadata.
	 */
	public ClientMetadata getClientMetadata() {

		return metadata;
	}
	
	
	/**
	 * Gets the client secret. Corresponds to the {@code client_secret} 
	 * registration parameters.
	 *
	 * @return The client secret, {@code null} if not specified.
	 */
	public Secret getClientSecret() {

		return secret;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException{
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, getEndpointURI());

		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
		
		JSONObject jsonObject = metadata.toJSONObject();
		
		jsonObject.put("client_id", id.getValue());
		
		if (secret != null)
			jsonObject.put("client_secret", secret.getValue());

		httpRequest.setQuery(jsonObject.toString());

		return httpRequest;
	}
	
	
	/**
	 * Parses a client update request from the specified HTTP PUT request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client update request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client update request.
	 */
	public static ClientUpdateRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.PUT);
		
		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest.getAuthorization());
		
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		
		ClientID id = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));

		ClientMetadata metadata = ClientMetadata.parse(jsonObject);
		
		Secret clientSecret = null;
		
		if (jsonObject.get("client_secret") != null)
			clientSecret = new Secret(JSONObjectUtils.getString(jsonObject, "client_secret"));
			
		
		return new ClientUpdateRequest(httpRequest.getURL(), id, accessToken, metadata, clientSecret);
	}
}
