package com.nimbusds.openid.connect.messages;


import java.util.Map;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Base abstract class for client authentication at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-24)
 */
public abstract class ClientAuthentication {


	/**
	 * Enumeration of the OpenID Connect client authentication methods.
	 */
	public static enum Method {
	
	
		/**
		 * Clients that have received a {@code client_secret} value from the 
		 * authorisation server, authenticate with the authorisation server in 
		 * accordance with section 3.2.1 of OAuth 2.0 using HTTP Basic 
		 * authentication scheme. This is the default if no method has been
		 * registered for the client.
		 */
		CLIENT_SECRET_BASIC,


		/**
		 * Clients that have received a {@code client_secret} value from the 
		 * authorisation server, authenticate with the authorisation server in 
		 * accordance with section 3.2.1 of OAuth 2.0 by including the client 
		 * credentials in the request body.
		 */
		CLIENT_SECRET_POST,


		/**
		 * Clients that have received a {@code client_secret} value from the 
		 * authorisation server, create a JWT using an HMAC SHA algorithm, such 
		 * as HMAC SHA-256. The HMAC (Hash-based Message Authentication Code) is
		 * calculated using the value of {@code client_secret} as the shared 
		 * key. The client authenticates in accordance with section 2.2 of (JWT) 
		 * Bearer Token Profiles and OAuth 2.0 Assertion Profile. 
		 */
		CLIENT_SECRET_JWT,


		/**
		 * Clients that have registered a public key sign a JWT using the RSA 
		 * algorithm if a RSA key was registered or the ECDSA algorithm if an 
		 * Elliptic Curve key was registered (see JWA for the algorithm 
		 * identifiers). The client authenticates in accordance with section 2.2
		 * of (JWT) Bearer Token Profiles and OAuth 2.0 Assertion Profile.
		 */
		PRIVATE_KEY_JWT;
	}
	
	
	/**
	 * The client authentication method.
	 */
	private Method method;
	
	
	/**
	 * Creates a new abstract client authentication.
	 *
	 * @param method The client authentication method. Must not be 
	 *               {@code null}.
	 */
	protected ClientAuthentication(final Method method) {
	
		if (method == null)
			throw new IllegalArgumentException("The method must not be null");
		
		this.method = method;
	}
	
	
	/**
	 * Gets the client authentication method.
	 *
	 * @return The client authentication method.
	 */
	public Method getMethod() {
	
		return method;
	}
	
	
	/**
	 * Parses the specified HTTP request for a supported client 
	 * authentication (see {@link Method}). This method is intended to aid 
	 * parsing of authenticated {@link TokenRequest}s.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The client authentication method, {@code null} if none or the
	 *         method is not supported.
	 *
	 * @throws ParseException If the inferred client authentication couldn't
	 *                        be parsed.
	 */
	public static ClientAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
	
		// Check for client secret basic
		if (httpRequest.getAuthorization() != null && 
		    httpRequest.getAuthorization().startsWith("Basic"))

			return ClientSecretBasic.parse(httpRequest);
		
		// The other methods require HTTP POST with URL-encoded params
		if (httpRequest.getMethod() != HTTPRequest.Method.POST &&
		    ! httpRequest.getContentType().match(CommonContentTypes.APPLICATION_URLENCODED))
			return null;
		
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			return null;
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		// We have client secret post
		if (params.containsKey("client_id") && params.containsKey("client_secret"))
			return ClientSecretPost.parse(httpRequest);
		
		// Do we have a signed JWT assertion?
		if (params.containsKey("client_assertion") && params.containsKey("client_assertion_type"))
			return JWTClientAuthentication.parse(httpRequest);
		else
			return null;
	}
	
	
	/**
	 * Applies the authentication to the specified HTTP request by setting 
	 * its Authorization header and/or POST entity-body parameters 
	 * (according to the implemented client authentication method).
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @throws SerializeException If the client authentication parameters
	 *                            couldn't be applied to the HTTP request.
	 */
	public abstract void apply(final HTTPRequest httpRequest) throws SerializeException;
}
