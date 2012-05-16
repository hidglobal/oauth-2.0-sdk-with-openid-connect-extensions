package com.nimbusds.openid.connect.messages;


import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.ClientID;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Client secret JWT authentication at the Token endpoint. Implements
 * {@link ClientAuthentication.Method#CLIENT_SECRET_JWT}.
 *
 * <p>Supported signature JSON Web Algorithms (JWAs) by this implementation:
 *
 * <ul>
 *     <li>HS256
 *     <li>HS384
 *     <li>HS512
 * </ul>
 *
 * <p>See http://openid.net/specs/openid-connect-messages-1_0.html#client_authentication
 *
 * <p>See draft-ietf-oauth-assertions-03
 *
 * <p>See draft-jones-oauth-jwt-bearer-04
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-11)
 */
public class ClientSecretJWT extends JWTClientAuthentication {


	/**
	 * Gets the set of supported signature JSON Web Algorithms (JWAs) by 
	 * this implementation of client secret JSON Web Token (JWT) 
	 * authentication.
	 *
	 * @return The set of supported JSON Web Algorithms (JWAs).
	 */
	public static Set<JWA> getSupportedJWAs() {
	
		Set<JWA> supported = new HashSet<JWA>();
		
		supported.add(JWA.HS256);
		supported.add(JWA.HS384);
		supported.add(JWA.HS512);
		
		return supported;
	}
	
	 
	/**
	 * Creates a new client secret JWT authentication.
	 *
	 * @param clientAssertion The client assertion, corresponding to the
	 *                        {@code client_assertion_parameter}, as an 
	 *                        HMAC-signed JWT. Must not be {@code null}.
	 * @param clientID        Optional client identifier, corresponding to
	 *                        the {@code client_id} parameter. {@code null}
	 *                        if not specified.
	 */
	public ClientSecretJWT(final SignedJWT clientAssertion, final ClientID clientID) {
	
		super(ClientAuthentication.Method.CLIENT_SECRET_JWT, clientAssertion, clientID);
	}
	
	
	/**
	 * Parses the specified parameters map for a client secret JSON Web 
	 * Token (JWT) authentication. Note that the parameters must not be
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @param params The parameters map to parse. The client secret JSON
	 *               Web Token (JWT) parameters must be keyed under 
	 *               "client_assertion" and "client_assertion_type". The 
	 *               map must not be {@code null}.
	 *
	 * @return The client secret JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters map couldn't be parsed to a 
	 *                        valid client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final Map<String,String> params)
		throws ParseException {
	
		JWTClientAuthentication.ensureClientAssertionType(params);
		
		SignedJWT clientAssertion = JWTClientAuthentication.parseClientAssertion(params);
		
		ClientID clientID = JWTClientAuthentication.parseClientID(params);
		
		JWA alg = clientAssertion.getHeader().getAlgorithm();
		
		if (getSupportedJWAs().contains(alg))
			throw new ParseException("The client assertion JWT must be HMAC-signed (HS256, HS384 or HS512)");
		
		return new ClientSecretJWT(clientAssertion, clientID);
	}
	
	
	/**
	 * Parses a client secret JSON Web Token (JWT) authentication from the 
	 * specified {@code application/x-www-form-urlencoded} encoded 
	 * parameters string.
	 *
	 * @param paramsString The parameters string to parse. The client secret
	 *                     JSON Web Token (JWT) parameters must be keyed 
	 *                     under "client_assertion" and 
	 *                     "client_assertion_type". The string must not be 
	 *                     {@code null}.
	 *
	 * @return The client secret JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters string couldn't be parsed to
	 *                        a valid client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final String paramsString)
		throws ParseException {
		
		Map<String,String> params = URLUtils.parseParameters(paramsString);
		
		return parse(params);
	}
	
	
	/**
	 * Parses the specified HTTP POST request for a client secret JSON Web 
	 * Token (JWT) authentication.
	 *
	 * @param httpRequest The HTTP POST request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    {@code application/x-www-form-urlencoded} encoded 
	 *                    parameters string in the entity body. The client 
	 *                    secret JSON Web Token (JWT) parameters must be 
	 *                    keyed under "client_assertion" and 
	 *                    "client_assertion_type".
	 *
	 * @return The client secret JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the HTTP request header couldn't be parsed
	 *                        to a valid client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getQueryParameters());
	}
}
