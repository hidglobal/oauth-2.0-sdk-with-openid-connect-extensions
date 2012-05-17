package com.nimbusds.openid.connect.messages;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Access token request to the Token endpoint.
 *
 * <p>Example HTTP request (with private key JWT client authentication):
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * 
 * grant_type=authorization_code&
 * code=i1WsRn1uB1&
 * client_id=s6BhdRkqt3&
 * client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
 * client_assertion=PHNhbWxwOl...[omitted for brevity]...ZT
 * </pre>
 *
 * <p>See http://tools.ietf.org/html/draft-ietf-oauth-v2-26#section-4.1.3
 *
 * <p>See draft-ietf-oauth-v2-26, section 4.1.3.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-17)
 */
public class AccessTokenRequest extends TokenRequest {
	
	
	/**
	 * The authorisation code received from the authorisation server.
	 */
	private AuthorizationCode code;
	
	
	/**
	 * The redirect URI.
	 */
	private URL redirectURI;
	
	
	/**
	 * Creates a new unauthenticated access token request with the specified
	 * parameters.
	 *
	 * @param code        The authorisation code received from the 
	 *                    authorisation server. Must not be {@code null}.
	 * @param redirectURI The redirect URI. Must not be {@code null}.
	 */
	public AccessTokenRequest(final AuthorizationCode code, final URL redirectURI) {
	
		this(code, redirectURI, null);
	}
	
	
	/**
	 * Creates a new authenticated access token request with the specified
	 * parameters.
	 *
	 * @param code        The authorisation code received from the 
	 *                    authorisation server. Must not be {@code null}.
	 * @param redirectURI The redirect URI. Must not be {@code null}.
	 * @param clientAuth  The client authentication, {@code null} if none.
	 */
	public AccessTokenRequest(final AuthorizationCode code, final URL redirectURI, final ClientAuthentication clientAuth) {
	
		super(GrantType.AUTHORIZATION_CODE, clientAuth);
		
		if (code == null)
			throw new NullPointerException("The authorization code must not be null");
		
		this.code = code;
		
		if (redirectURI == null)
			throw new NullPointerException("The redirect URI must not be null");
		
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
	
	
	/**
	 * Returns the HTTP request for this access token request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If this access token request couldn't be 
	 *                            serialised to an HTTP request.
	 */
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
