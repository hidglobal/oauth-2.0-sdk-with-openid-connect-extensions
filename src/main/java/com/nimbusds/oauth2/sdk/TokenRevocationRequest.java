package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Token revocation request. Used to revoke an issued access or refresh token.
 *
 * <p>Example token revocation request with client authentication:
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
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Revocation (RFC 7009), section 2.1.
 * </ul>
 */
@Immutable
public final class TokenRevocationRequest extends AbstractRequest {


	/**
	 * The client authentication, {@code null} if none.
	 */
	private final ClientAuthentication clientAuth;


	/**
	 * The token to revoke.
	 */
	private final Token token;


	/**
	 *
	 * @param uri        The URI of the token revocation endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientAuth The client authentication, {@code null} if none.
	 * @param token      The access or refresh token to revoke. Must not be
	 *                   {@code null}.
	 */
	public TokenRevocationRequest(final URI uri,
				      final ClientAuthentication clientAuth,
				      final Token token) {

		super(uri);

		this.clientAuth = clientAuth;

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
	}


	/**
	 * Gets the client authentication.
	 *
	 * @return The client authentication, {@code null} if none.
	 */
	public ClientAuthentication getClientAuthentication() {

		return clientAuth;
	}


	/**
	 * Returns the token to revoke. The {@code instanceof} operator can be
	 * used to infer the token type. If it's neither
	 * {@link com.nimbusds.oauth2.sdk.token.AccessToken} nor
	 * {@link com.nimbusds.oauth2.sdk.token.RefreshToken} the
	 * {@code token_type_hint} has not be provided as part of the token
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
		params.put("token", token.getValue());

		if (token instanceof AccessToken) {
			params.put("token_type_hint", "access_token");
		} else if (token instanceof RefreshToken) {
			params.put("token_type_hint", "refresh_token");
		}

		httpRequest.setQuery(URLUtils.serializeParameters(params));

		if (getClientAuthentication() != null)
			getClientAuthentication().applyTo(httpRequest);

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
				public Set<String> getParamNames() {

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


		// Parse client auth
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		URI uri;

		try {
			uri = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}

		return new TokenRevocationRequest(uri, clientAuth, token);
	}
}
