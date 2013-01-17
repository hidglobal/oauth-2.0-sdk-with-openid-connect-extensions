package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Access token request to the Token endpoint. Used to obtain an 
 * {@link AccessToken access token} and an optional 
 * {@link RefreshToken refresh token} from the authorisation server. This class
 * is immutable.
 *
 * <p>Supported authorisation grant types:
 *
 * <ul>
 *     <li>{@link GrantType#AUTHORIZATION_CODE Authorisation code}
 *     <li>{@link GrantType#PASSWORD Resource owner password credentials}
 *     <li>{@link GrantType#CLIENT_CREDENTIALS Client credentials}
 * </ul>
 *
 * <p>Example HTTP request, with {@link ClientSecretBasic client secret basic}
 * authentication:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
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
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.3, 4.3.2 and 4.4.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
@Immutable
public final class AccessTokenRequest extends TokenRequest {
	
	
	// Authorisation code grant

	/**
	 * The authorisation code received from the authorisation server.
	 */
	private final AuthorizationCode code;
	
	
	/**
	 * The conditionally required redirect URI in the initial authorisation
	 * request.
	 */
	private final URL redirectURI;


	/**
	 * The conditionally required client ID.
	 */
	private final ClientID clientID;


	// Password credentials grant

	/**
	 * The username.
	 */
	private final String username;


	/**
	 * The password.
	 */
	private final String password;


	// For password + client credentials grant

	/**
	 * The access scope.
	 */
	private final Scope scope;
	
	
	/**
	 * Creates a new unauthenticated access token request, using an
	 * {@link GrantType#AUTHORIZATION_CODE authorisation code grant}.
	 *
	 * @param code        The authorisation code received from the 
	 *                    authorisation server. Must not be {@code null}.
	 * @param redirectURI The redirect URI, may be {@code null} if not
	 *                    specified in the initial authorisation request.
	 * @param clientID    The client identifier. Must not be {@code null}.
	 */
	public AccessTokenRequest(final AuthorizationCode code, 
		                  final URL redirectURI,
		                  final ClientID clientID) {
	
		super(GrantType.AUTHORIZATION_CODE, null);

		if (code == null)
			throw new IllegalArgumentException("The authorization code must not be null");
		
		this.code = code;


		this.redirectURI = redirectURI;


		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		this.clientID = clientID;


		username = null;
		password = null;
		scope = null;
	}
	
	
	/**
	 * Creates a new authenticated access token request, using an
	 * {@link GrantType#AUTHORIZATION_CODE authorisation code grant}. 
	 *
	 * @param code        The authorisation code received from the 
	 *                    authorisation server. Must not be {@code null}.
	 * @param redirectURI The redirect URI, may be {@code null} if not
	 *                    specified in the initial authorisation request.
	 * @param clientAuth  The client authentication. Must not be 
	 *                    {@code null}.
	 */
	public AccessTokenRequest(final AuthorizationCode code, 
		                  final URL redirectURI, 
	                          final ClientAuthentication clientAuth) {
	
		super(GrantType.AUTHORIZATION_CODE, clientAuth);
		
		if (code == null)
			throw new IllegalArgumentException("The authorization code must not be null");
		
		this.code = code;
		
		this.redirectURI = redirectURI;

		if (clientAuth == null)
			throw new IllegalArgumentException("The client authentication must not be null");


		clientID = null;
		username = null;
		password = null;
		scope = null;
	}


	/**
	 * Creates a new authenticated access token request, using a
	 * {@link GrantType#PASSWORD resource owner password credentials grant}.
	 *
	 * @param username The resource owner username. Must not be 
	 *                 {@code null}.
	 * @param password The resource owner password. Must not be 
	 *                 {@code null}.
	 * @param scope    The scope of the access request, {@code null} if not
	 *                 specified.
	 */
	public AccessTokenRequest(final String username, 
		                  final String password,
		                  final Scope scope) {
	
		super(GrantType.PASSWORD, null);

		if (username == null)
			throw new IllegalArgumentException("The username must not be null");

		this.username = username;


		if (password == null)
			throw new IllegalArgumentException("The password must not be null");

		this.password = password;

		this.scope = scope;

		code = null;
		redirectURI = null;
		clientID = null;
	}


	/**
	 * Creates a new authenticated access token request, using a
	 * {@link GrantType#CLIENT_CREDENTIALS client credentials grant}.
	 *
	 * @param scope      The scope of the access request, {@code null} if 
	 *                   not specified.
	 * @param clientAuth The client authentication. Must not be 
	 *                   {@code null}.
	 */
	public AccessTokenRequest(final Scope scope, 
		                  final ClientAuthentication clientAuth) {
	
		super(GrantType.CLIENT_CREDENTIALS, null);

		this.scope = scope;

		if (clientAuth == null)
			throw new IllegalArgumentException("The client authentication must not be null");

		code = null;
		redirectURI = null;
		clientID = null;
		username = null;
		password = null;
	}
	
	
	/**
	 * Gets the authorisation code. Applies to requests using an
	 * {@link GrantType#AUTHORIZATION_CODE authorisation code grant}.
	 *
	 * @return The authorisation code, {@code null} if not specified.
	 */
	public AuthorizationCode getAuthorizationCode() {
	
		return code;
	}
	
	
	/**
	 * Gets the redirect URI. Applies to requests using an
	 * {@link GrantType#AUTHORIZATION_CODE authorisation code grant}
	 *
	 * @return The redirect URI, {@code null} if not specified.
	 */
	public URL getRedirectURI() {
	
		return redirectURI;
	}


	/**
	 * Gets the client identifier. Applies to requests using an
	 * {@link GrantType#AUTHORIZATION_CODE authorisation code grant}.
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return clientID;
	}


	/**
	 * Gets the resource owner username. Applies to requests using a
	 * {@link GrantType#PASSWORD resource owner password credentials
	 * grant}.
	 *
	 * @return The resource owner username, {@code null} if not specified.
	 */
	public String getUsername() {

		return username;
	}


	/**
	 * Gets the resource owner password. Applies to requests using a
	 * {@link GrantType#PASSWORD resource owner password credentials
	 * grant}.
	 *
	 * @return The resource owner password, {@code null} if not specified.
	 */
	public String getPassword() {

		return password;
	}


	/**
	 * Gets the access scope. Applies to requests using a
	 * {@link GrantType#PASSWORD resource owner password credentials} or
	 * {@link GrantType#CLIENT_CREDENTIALS client credentials grant}.
	 *
	 * @return The access scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		Map<String,String> params = new LinkedHashMap<String,String>();

		params.put("grant_type", getGrantType().toString());

		if (getGrantType().equals(GrantType.AUTHORIZATION_CODE)) {

			params.put("code", code.toString());

			if (redirectURI != null)
				params.put("redirect_uri", redirectURI.toString());

			if (clientID != null)
				params.put("client_id", clientID.getValue());
		}
		else if (getGrantType().equals(GrantType.PASSWORD)) {

			params.put("username", username);

			params.put("password", password);

			if (scope != null)
				params.put("scope", scope.toString());

		}
		else if (getGrantType().equals(GrantType.CLIENT_CREDENTIALS)) {

			if (scope != null)
				params.put("scope", scope.toString());
		}
		else {
			throw new SerializeException("Unsupported grant type: " + getGrantType());
		}
		
		httpRequest.setQuery(URLUtils.serializeParameters(params));
		
		if (getClientAuthentication() != null)
			getClientAuthentication().apply(httpRequest);
		
		return httpRequest;	
	}
	
	
	/**
	 * Parses the specified HTTP request for an access token request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The access token request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        access token request.
	 */
	public static AccessTokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		// No fragment!
		// May use query component!
		Map<String,String> params = httpRequest.getQueryParameters();
		
		
		// Parse grant type
		String grantTypeString = params.get("grant_type");
		
		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter");

		GrantType grantType = new GrantType(grantTypeString);
			
		if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {

			// Parse authorisation code
			String codeString = params.get("code");
		
			if (codeString == null)
				throw new ParseException("Missing \"code\" parameter");
		
			AuthorizationCode code = new AuthorizationCode(codeString);
		
		
			// Parse redirect URI
			String redirectURIString = params.get("redirect_uri");
			
			URL redirectURI = null;

			if (redirectURIString != null) {
			
				try {
					redirectURI = new URL(redirectURIString);
					
				} catch (MalformedURLException e) {
				
					throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), e);
				}
			}


			// Parse client ID
			String clientIDString = params.get("client_id");

			ClientID clientID = null;

			if (clientIDString != null)
				clientID = new ClientID(clientIDString);

			// Parse client authentication
			ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

			if (clientAuth != null && clientID == null)
				return new AccessTokenRequest(code, redirectURI, clientAuth);

			else if (clientAuth == null && clientID != null)
				return new AccessTokenRequest(code, redirectURI, clientID);

			else
				throw new ParseException("Client authentication conflicts with \"client_id\" parameter");
		}
		else if (grantType.equals(GrantType.PASSWORD)) {

			String username = params.get("username");

			if (username == null)
				throw new ParseException("Missing \"username\" parameter");

			String password = params.get("password");

			if (password == null)
				throw new ParseException("Missing \"password\" parameter");

			Scope scope = Scope.parse(params.get("scope"));

			return new AccessTokenRequest(username, password, scope);
		}
		else if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {

			Scope scope = Scope.parse(params.get("scope"));

			ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

			if (clientAuth == null)
				throw new ParseException("Missing client authentication");

			return new AccessTokenRequest(scope, clientAuth);
				
		}
		else {
			throw new ParseException("Unsupported grant type: " + grantType);
		}
	}
}
