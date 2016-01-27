package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;


/**
 * Token revocation request. Used to revoke an issued access or refresh token.
 *
 * <p>Example token revocation request for a confidential client:
 *
 * <pre>
 * POST /revoke HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token
 * </pre>
 *
 * <p>Example token revocation request for a public client:
 *
 * <pre>
 * POST /revoke HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token&client_id=123456
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Revocation (RFC 7009), section 2.1.
 * </ul>
 */
@Immutable
public final class TokenRevocationRequest extends AbstractOptionallyAuthenticatedRequest {


	/**
	 * The client identifier, {@code null} if not specified.
	 */
	private final ClientID clientID;


	/**
	 * The token to revoke.
	 */
	private final Token token;


	/**
	 * Creates a new token revocation request for a confidential client.
	 *
	 * @param uri        The URI of the token revocation endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param token      The access or refresh token to revoke. Must not be
	 *                   {@code null}.
	 */
	public TokenRevocationRequest(final URI uri,
				      final ClientAuthentication clientAuth,
				      final Token token) {

		super(uri, clientAuth);

		if (clientAuth == null) {
			throw new IllegalArgumentException("The client authentication must not be null");
		}

		clientID = null;

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
	}


	/**
	 * Creates a new token revocation request for a public client.
	 *
	 * @param uri      The URI of the token revocation endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method
	 *                 will not be used.
	 * @param clientID The client ID. Must not be {@code null}.
	 * @param token    The access or refresh token to revoke. Must not be
	 *                 {@code null}.
	 */
	public TokenRevocationRequest(final URI uri,
				      final ClientID clientID,
				      final Token token) {

		super(uri, null);

		if (clientID == null) {
			throw new IllegalArgumentException("The client ID must not be null");
		}

		this.clientID = clientID;

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
	}


	/**
	 * Gets the client identifier (for a token revocation request by a
	 * public client).
	 *
	 * @see #getClientAuthentication()
	 *
	 * @return The client identifier, {@code null} if the client is
	 *         confidential.
	 */
	public ClientID getClientID() {

		return clientID;
	}


	/**
	 * Returns the token to revoke. The {@code instanceof} operator can be
	 * used to infer the token type. If it's neither
	 * {@link com.nimbusds.oauth2.sdk.token.AccessToken} nor
	 * {@link com.nimbusds.oauth2.sdk.token.RefreshToken} the
	 * {@code token_type_hint} has not been provided as part of the token
	 * revocation request.
	 *
	 * @return The token.
	 */
	public Token getToken() {

		return token;
	}


	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		URL url;

		try {
			url = getEndpointURI().toURL();

		} catch (MalformedURLException e) {

			throw new SerializeException(e.getMessage(), e);
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> params = new HashMap<>();

		if (getClientID() != null) {
			// public client
			params.put("client_id", getClientID().getValue());
		}

		params.put("token", token.getValue());

		if (token instanceof AccessToken) {
			params.put("token_type_hint", "access_token");
		} else if (token instanceof RefreshToken) {
			params.put("token_type_hint", "refresh_token");
		}

		httpRequest.setQuery(URLUtils.serializeParameters(params));

		if (getClientAuthentication() != null) {
			// confidential client
			getClientAuthentication().applyTo(httpRequest);
		}

		return httpRequest;
	}


	/**
	 * Parses a token revocation request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token revocation request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token revocation request.
	 */
	public static TokenRevocationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> params = httpRequest.getQueryParameters();

		final String tokenValue = params.get("token");

		if (tokenValue == null || tokenValue.isEmpty()) {
			throw new ParseException("Missing required token parameter");
		}

		// Detect the token type
		Token token = null;

		final String tokenTypeHint = params.get("token_type_hint");

		if (tokenTypeHint == null) {

			// Can be both access or refresh token
			token = new Token() {

				@Override
				public String getValue() {

					return tokenValue;
				}

				@Override
				public Set<String> getParameterNames() {

					return Collections.emptySet();
				}

				@Override
				public JSONObject toJSONObject() {

					return new JSONObject();
				}

				@Override
				public boolean equals(final Object other) {

					return other instanceof Token && other.toString().equals(tokenValue);
				}
			};

		} else if (tokenTypeHint.equals("access_token")) {

			token = new TypelessAccessToken(tokenValue);

		} else if (tokenTypeHint.equals("refresh_token")) {

			token = new RefreshToken(tokenValue);
		}

		URI uri;

		try {
			uri = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}

		// Parse client auth
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		if (clientAuth != null) {
			return new TokenRevocationRequest(uri, clientAuth, token);
		}

		// Public client
		final String clientIDString = params.get("client_id");

		if (StringUtils.isBlank(clientIDString)) {
			throw new ParseException("Invalid token revocation request: No client authentication or client_id parameter found");
		}

		return new TokenRevocationRequest(uri, new ClientID(clientIDString), token);
	}
}
