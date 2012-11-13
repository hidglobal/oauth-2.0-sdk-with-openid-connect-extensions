package com.nimbusds.openid.connect.sdk.messages;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPRequest;

import com.nimbusds.openid.connect.sdk.util.URLUtils;


/**
 * Access token request to the Token endpoint. Used to obtain an 
 * {@link AccessToken access token}, {@link RefreshToken refresh token} or an
 * {@link com.nimbusds.openid.connect.sdk.claims.sets.IDTokenClaims ID token}. 
 * This class is immutable.
 *
 * <p>Example HTTP request, with {@link ClientSecretBasic client secret basic
 * authentication}:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * 
 * grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
 * &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.2.
 *     <li>OpenID Connect Standard 1.0, section 3.1.1.
 *     <li>OAuth 2.0 (RFC 6749), section 4.1.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@Immutable
public final class AccessTokenRequest extends TokenRequest {
	
	
	/**
	 * The authorisation code received from the authorisation server.
	 */
	private final AuthorizationCode code;
	
	
	/**
	 * The redirect URI.
	 */
	private final URL redirectURI;
	
	
	/**
	 * Creates a new unauthenticated access token request.
	 *
	 * @param code        The authorisation code received from the 
	 *                    authorisation server. Must not be {@code null}.
	 * @param redirectURI The redirect URI. Must not be {@code null}.
	 */
	public AccessTokenRequest(final AuthorizationCode code, final URL redirectURI) {
	
		this(code, redirectURI, null);
	}
	
	
	/**
	 * Creates a new authenticated access token request.
	 *
	 * @param code        The authorisation code received from the 
	 *                    authorisation server. Must not be {@code null}.
	 * @param redirectURI The redirect URI. Must not be {@code null}.
	 * @param clientAuth  The client authentication, {@code null} if none.
	 */
	public AccessTokenRequest(final AuthorizationCode code, 
		                  final URL redirectURI, 
	                          final ClientAuthentication clientAuth) {
	
		super(GrantType.AUTHORIZATION_CODE, clientAuth);
		
		if (code == null)
			throw new IllegalArgumentException("The authorization code must not be null");
		
		this.code = code;
		
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
		
		this.redirectURI = redirectURI;
	}
	
	
	/**
	 * Gets the authorisation code.
	 *
	 * @return The authorisation code.
	 */
	public AuthorizationCode getAuthorizationCode() {
	
		return code;
	}
	
	
	/**
	 * Gets the redirect URI.
	 *
	 * @return The redirect URI.
	 */
	public URL getRedirectURI() {
	
		return redirectURI;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		Map<String,String> params = new LinkedHashMap<String,String>();
		params.put("grant_type", getGrantType().toString());
		params.put("code", code.toString());
		params.put("redirect_uri", redirectURI.toString());
		
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
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid access token request.
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
		final String grantTypeString = params.get("grant_type");
		
		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter");
			
		if (! grantTypeString.equals(GrantType.AUTHORIZATION_CODE.toString()))
			throw new ParseException("Invalid \"grant_type\" parameter: " + grantTypeString);
		
		
		// Parse authorisation code
		final String codeString = params.get("code");
		
		if (codeString == null)
			throw new ParseException("Missing \"code\" parameter");
		
		
		AuthorizationCode code = new AuthorizationCode(codeString);
		
		
		// Parse redirect URI
		final String redirectURIString = params.get("redirect_uri");
		
		if (redirectURIString == null) 
			throw new ParseException("Missing \"redirect_uri\" parameter");
		
		URL redirectURI = null;
		
		try {
			redirectURI = new URL(redirectURIString);
			
		} catch (MalformedURLException e) {
		
			throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), e);
		}
		
		// Parse client authentication
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);
		
		return new AccessTokenRequest(code, redirectURI, clientAuth);
	}
}
