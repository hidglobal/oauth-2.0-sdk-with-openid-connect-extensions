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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;


/**
 * Token introspection request. Used by a protected resource to obtain the
 * authorisation for a submitted access token. May also be used by clients to
 * query a refresh token.
 *
 * <p>The protected resource may be required to authenticate itself to the
 * token introspection endpoint with a standard client
 * {@link ClientAuthentication authentication method}, such as
 * {@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic client_secret_basic},
 * or with a dedicated {@link AccessToken access token}.
 *
 * <p>Example token introspection request, where the protected resource
 * authenticates itself with a secret (the token type is also hinted):
 *
 * <pre>
 * POST /introspect HTTP/1.1
 * Host: server.example.com
 * Accept: application/json
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * token=mF_9.B5f-4.1JqM&token_type_hint=access_token
 * </pre>
 *
 * <p>Example token introspection request, where the protected resource
 * authenticates itself with a bearer token:
 *
 * <pre>
 * POST /introspect HTTP/1.1
 * Host: server.example.com
 * Accept: application/json
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Bearer 23410913-abewfq.123483
 *
 * token=2YotnFZFEjr1zCsicMWpAA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 * </ul>
 */
@Immutable
public class TokenIntrospectionRequest extends AbstractOptionallyAuthenticatedRequest {


	/**
	 * The token to introspect.
	 */
	private final Token token;


	/**
	 * Optional access token to authorise the submitter.
	 */
	private final AccessToken clientAuthz;


	/**
	 * Optional additional parameters.
	 */
	private final Map<String,String> customParams;


	/**
	 * Creates a new token introspection request. The request submitter is
	 * not authenticated.
	 *
	 * @param uri   The URI of the token introspection endpoint. May be
	 *              {@code null} if the {@link #toHTTPRequest} method will
	 *              not be used.
	 * @param token The access or refresh token to introspect. Must not be
	 *              {@code null}.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final Token token) {

		this(uri, token, null);
	}


	/**
	 * Creates a new token introspection request. The request submitter is
	 * not authenticated.
	 *
	 * @param uri          The URI of the token introspection endpoint. May
	 *                     be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param token        The access or refresh token to introspect. Must
	 *                     not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final Token token,
					 final Map<String,String> customParams) {

		super(uri, null);

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
		this.clientAuthz = null;
		this.customParams = customParams != null ? customParams : Collections.<String,String>emptyMap();
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authenticate with a secret or private key JWT assertion.
	 *
	 * @param uri        The URI of the token introspection endpoint. May
	 *                   be {@code null} if the {@link #toHTTPRequest}
	 *                   method will not be used.
	 * @param clientAuth The client authentication, {@code null} if none.
	 * @param token      The access or refresh token to introspect. Must
	 *                   not be {@code null}.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final ClientAuthentication clientAuth,
					 final Token token) {

		this(uri, clientAuth, token, null);
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authenticate with a secret or private key JWT assertion.
	 *
	 * @param uri          The URI of the token introspection endpoint. May
	 *                     be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param clientAuth   The client authentication, {@code null} if none.
	 * @param token        The access or refresh token to introspect. Must
	 *                     not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final ClientAuthentication clientAuth,
					 final Token token,
					 final Map<String,String> customParams) {

		super(uri, clientAuth);

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
		this.clientAuthz = null;
		this.customParams = customParams != null ? customParams : Collections.<String,String>emptyMap();
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authorise itself with an access token.
	 *
	 * @param uri         The URI of the token introspection endpoint. May
	 *                    be {@code null} if the {@link #toHTTPRequest}
	 *                    method will not be used.
	 * @param clientAuthz The client authorisation, {@code null} if none.
	 * @param token       The access or refresh token to introspect. Must
	 *                    not be {@code null}.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final AccessToken clientAuthz,
					 final Token token) {

		this(uri, clientAuthz, token, null);
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authorise itself with an access token.
	 *
	 * @param uri          The URI of the token introspection endpoint. May
	 *                     be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param clientAuthz  The client authorisation, {@code null} if none.
	 * @param token        The access or refresh token to introspect. Must
	 *                     not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final AccessToken clientAuthz,
					 final Token token,
					 final Map<String,String> customParams) {

		super(uri, null);

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
		this.clientAuthz = clientAuthz;
		this.customParams = customParams != null ? customParams : Collections.<String,String>emptyMap();
	}


	/**
	 * Returns the client authorisation.
	 *
	 * @return The client authorisation as an access token, {@code null} if
	 *         none.
	 */
	public AccessToken getClientAuthorization() {

		return clientAuthz;
	}


	/**
	 * Returns the token to introspect. The {@code instanceof} operator can
	 * be used to infer the token type. If it's neither
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


	/**
	 * Returns the custom request parameters.
	 *
	 * @return The custom request parameters, empty map if none.
	 */
	public Map<String,String> getCustomParameters() {

		return customParams;
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

		params.putAll(customParams);

		httpRequest.setQuery(URLUtils.serializeParameters(params));

		if (getClientAuthentication() != null)
			getClientAuthentication().applyTo(httpRequest);

		if (clientAuthz != null)
			httpRequest.setAuthorization(clientAuthz.toAuthorizationHeader());

		return httpRequest;
	}


	/**
	 * Parses a token introspection request from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token introspection request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token introspection request.
	 */
	public static TokenIntrospectionRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> params = httpRequest.getQueryParameters();

		final String tokenValue = params.remove("token");

		if (tokenValue == null || tokenValue.isEmpty()) {
			throw new ParseException("Missing required token parameter");
		}

		// Detect the token type
		Token token = null;

		final String tokenTypeHint = params.remove("token_type_hint");

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

		// Important: auth methods mutually exclusive!

		// Parse optional client auth
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		// Parse optional client authz (token)
		AccessToken clientAuthz = null;

		if (clientAuth == null && httpRequest.getAuthorization() != null) {
			clientAuthz = AccessToken.parse(httpRequest.getAuthorization());
		}

		URI uri;

		try {
			uri = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}

		if (clientAuthz != null) {
			return new TokenIntrospectionRequest(uri, clientAuthz, token, params);
		} else {
			return new TokenIntrospectionRequest(uri, clientAuth, token, params);
		}
	}
}
