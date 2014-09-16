package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Token request. Used to obtain an
 * {@link com.nimbusds.oauth2.sdk.token.AccessToken access token} and an
 * optional {@link com.nimbusds.oauth2.sdk.token.RefreshToken refresh token}
 * at the Token endpoint of the authorisation server.
 *
 * <p>Example token request with an authorisation code grant:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-URIencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * grant_type=authorization_code
 * &amp;code=SplxlOBeZQQYbYS6WxSbIA
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.3, 4.3.2, 4.4.2 and 6.
 * </ul>
 */
@Immutable
public class TokenRequest extends AbstractRequest {


	/**
	 * The client authentication, {@code null} if none.
	 */
	private final ClientAuthentication clientAuth;


	/**
	 * The client identifier, {@code null} if not specified.
	 */
	private final ClientID clientID;


	/**
	 * The authorisation grant.
	 */
	private final AuthorizationGrant authzGrant;


	/**
	 * The requested scope, {@code null} if not specified.
	 */
	private final Scope scope;


	/**
	 * Creates a new token request with the specified client
	 * authentication.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		super(uri);

		if (clientAuth == null)
			throw new IllegalArgumentException("The client authentication must not be null");

		this.clientAuth = clientAuth;

		clientID = null; // must not be set when client auth is present

		this.authzGrant = authzGrant;

		this.scope = scope;
	}


	/**
	 * Creates a new token request with the specified client
	 * authentication.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URI uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant) {

		this(uri, clientAuth, authzGrant, null);
	}


	/**
	 * Creates a new token request, with no explicit client authentication
	 * (may be present in the grant depending on its type).
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientID   The client identifier, {@code null} if not
	 *                   specified.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI uri,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		super(uri);

		if (authzGrant.getType().requiresClientAuthentication()) {
			throw new IllegalArgumentException("The \"" + authzGrant.getType() + "\" grant type requires client authentication");
		}

		if (authzGrant.getType().requiresClientID() && clientID == null) {
			throw new IllegalArgumentException("The \"" + authzGrant.getType() + "\" grant type requires a \"client_id\" parameter");
		}

		this.authzGrant = authzGrant;

		this.clientID = clientID;
		clientAuth = null;

		this.scope = scope;
	}


	/**
	 * Creates a new token request, with no explicit client authentication
	 * (may be present in the grant depending on its type).
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientID   The client identifier, {@code null} if not
	 *                   specified.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URI uri,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant) {

		this(uri, clientID, authzGrant, null);
	}


	/**
	 * Creates a new token request, without client authentication and a
	 * specified client identifier.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI uri,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(uri, (ClientID)null, authzGrant, scope);
	}


	/**
	 * Creates a new token request, without client authentication and a
	 * specified client identifier.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URI uri,
			    final AuthorizationGrant authzGrant) {

		this(uri, (ClientID)null, authzGrant, null);
	}


	/**
	 * Gets the client authentication.
	 *
	 * @see #getClientID()
	 *
	 * @return The client authentication, {@code null} if none.
	 */
	public ClientAuthentication getClientAuthentication() {

		return clientAuth;
	}


	/**
	 * Gets the client identifier (for a token request without explicit
	 * client authentication).
	 *
	 * @see #getClientAuthentication()
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return clientID;
	}



	/**
	 * Gets the authorisation grant.
	 *
	 * @return The authorisation grant.
	 */
	public AuthorizationGrant getAuthorizationGrant() {

		return authzGrant;
	}


	/**
	 * Gets the requested scope.
	 *
	 * @return The requested scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {

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

		if (getClientAuthentication() != null) {
			getClientAuthentication().applyTo(httpRequest);
		}

		Map<String,String> params = httpRequest.getQueryParameters();

		params.putAll(authzGrant.toParameters());

		if (scope != null && ! scope.isEmpty()) {
			params.put("scope", scope.toString());
		}

		if (clientID != null) {
			params.put("client_id", clientID.getValue());
		}

		httpRequest.setQuery(URLUtils.serializeParameters(params));

		return httpRequest;
	}


	/**
	 * Parses a token request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token request.
	 */
	public static TokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		URI uri;

		try {
			uri = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}

		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

		// Parse client authentication, if any
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		// No fragment! May use query component!
		Map<String,String> params = httpRequest.getQueryParameters();

		// Parse grant
		AuthorizationGrant grant = AuthorizationGrant.parse(params);

		if (clientAuth == null && grant.getType().requiresClientAuthentication()) {
			throw new ParseException("Missing client authentication", OAuth2Error.INVALID_CLIENT);
		}

		// Parse client id
		ClientID clientID = null;

		if (clientAuth == null) {

			// Parse optional client ID
			String clientIDString = params.get("client_id");

			if (clientIDString != null && clientIDString.trim().length() > 0)
				clientID = new ClientID(clientIDString);

			if (clientID == null && grant.getType().requiresClientID()) {
				throw new ParseException("Missing required \"client_id\" parameter", OAuth2Error.INVALID_REQUEST);
			}
		}

		// Parse optional scope
		String scopeValue = params.get("scope");

		Scope scope = null;

		if (scopeValue != null) {
			scope = Scope.parse(scopeValue);
		}


		if (clientAuth != null) {
			return new TokenRequest(uri, clientAuth, grant, scope);
		} else {
			return new TokenRequest(uri, clientID, grant, scope);
		}
	}
}
