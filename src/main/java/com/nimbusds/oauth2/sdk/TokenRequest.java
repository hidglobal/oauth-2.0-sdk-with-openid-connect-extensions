package com.nimbusds.oauth2.sdk;


import java.net.URL;
import java.util.Map;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Token request. Used to obtain an
 * {@link com.nimbusds.oauth2.sdk.token.AccessToken access token} and an
 * optional {@link com.nimbusds.oauth2.sdk.token.RefreshToken refresh token}
 * at the Token endpoint of the authorisation server. This class is immutable.
 *
 * <p>Example token request with an authorisation code grant:
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
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.3, 4.3.2, 4.4.2 and 6.
 * </ul>
 */
public class TokenRequest extends AbstractRequest {


	/**
	 * The client authentication, {@code null} if none.
	 */
	private final ClientAuthentication clientAuth;


	/**
	 * The authorisation grant.
	 */
	private final AuthorizationGrant authzGrant;
	
	
	/**
	 * Creates a new token request.
	 *
	 * @param uri        The URI of the token endpoint. May be 
	 *                   {@code null} if the {@link #toHTTPRequest()}
	 *                   method will not be used.
	 * @param clientAuth The client authentication, {@code null} if none.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URL uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant) {
	
		super(uri);
		
		this.clientAuth = clientAuth;

		if (authzGrant == null)
			throw new IllegalArgumentException("The authorization grant must not be null");

		this.authzGrant = authzGrant;
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
	 * Gets the authorisation grant.
	 *
	 * @return The authorisation grant.
	 */
	public AuthorizationGrant getAuthorizationGrant() {

		return authzGrant;
	}


	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {

		if (getURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getURI());
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> params = authzGrant.toParameters();

		httpRequest.setQuery(URLUtils.serializeParameters(params));

		if (getClientAuthentication() != null)
			getClientAuthentication().applyTo(httpRequest);

		return httpRequest;
	}
	
	
	/**
	 * Parses the specified HTTP request for a token request.
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
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		// No fragment!
		// May use query component!
		Map<String,String> params = httpRequest.getQueryParameters();

		// Parse grant
		AuthorizationGrant authzGrant = AuthorizationGrant.parse(params);

		// Parse client auth
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		return new TokenRequest(httpRequest.getURL(), clientAuth, authzGrant);
	}
}
