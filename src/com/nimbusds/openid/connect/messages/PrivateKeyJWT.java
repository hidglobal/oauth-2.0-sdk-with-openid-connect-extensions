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
 * Private key JWT authentication at the Token endpoint. Implements
 * {@link ClientAuthentication.Method#PRIVATE_KEY_JWT}.
 *
 * <p>Supported signature JSON Web Algorithms (JWAs) by this implementation:
 *
 * <ul>
 *     <li>RS256
 *     <li>RS384
 *     <li>RS512
 *     <li>ES256
 *     <li>ES384
 *     <li>ES512
 * </ul>
 *
 * <p>Example {@link TokenRequest} with private key JWT authentication:
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
 * <p>See http://openid.net/specs/openid-connect-messages-1_0.html#client_authentication
 *
 * <p>See draft-ietf-oauth-assertions-03
 *
 * <p>See draft-jones-oauth-jwt-bearer-04
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-11)
 */
public class PrivateKeyJWT extends JWTClientAuthentication {


	/**
	 * Gets the set of supported signature JSON Web Algorithms (JWAs) by 
	 * this implementation of private key JSON Web Token (JWT) 
	 * authentication.
	 *
	 * @return The set of supported JSON Web Algorithms (JWAs).
	 */
	public static Set<JWA> getSupportedJWAs() {
	
		Set<JWA> supported = new HashSet<JWA>();
		
		supported.add(JWA.RS256);
		supported.add(JWA.RS384);
		supported.add(JWA.RS512);
		
		supported.add(JWA.ES256);
		supported.add(JWA.ES384);
		supported.add(JWA.ES512);
		
		return supported;
	}
	
	
	/**
	 * Creates a private key JWT authentication.
	 *
	 * @param clientAssertion The client assertion, corresponding to the
	 *                        {@code client_assertion} parameter, as an RSA 
	 *                        or ECDSA-signed JWT. Must not be {@code null}.
	 * @param clientID        Optional client identifier, corresponding to
	 *                        the {@code client_id} parameter. {@code null}
	 *                        if not specified.
	 */
	public PrivateKeyJWT(final SignedJWT clientAssertion, final ClientID clientID) {
	
		super(ClientAuthentication.Method.PRIVATE_KEY_JWT, clientAssertion, clientID);
	}
	
	
	/**
	 * Parses the specified parameters map for a private key JSON Web Token
	 * (JWT) authentication. Note that the parameters must not be
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @param params The parameters map to parse. The private key JSON
	 *               Web Token (JWT) parameters must be keyed under 
	 *               "client_assertion" and "client_assertion_type". The 
	 *               map must not be {@code null}.
	 *
	 * @return The private key JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters map couldn't be parsed to a 
	 *                        valid private key JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static PrivateKeyJWT parse(final Map<String,String> params)
		throws ParseException {
	
		JWTClientAuthentication.ensureClientAssertionType(params);
		
		SignedJWT clientAssertion = JWTClientAuthentication.parseClientAssertion(params);
		
		ClientID clientID = JWTClientAuthentication.parseClientID(params);
		
		JWA alg = clientAssertion.getHeader().getAlgorithm();
		
		if (getSupportedJWAs().contains(alg))
			throw new ParseException("The client assertion JWT must be RSA or ECDSA-signed (RS256, RS384, RS512, RS245, ES384 or ES512)");
		
		return new PrivateKeyJWT(clientAssertion, clientID);
	}
	
	
	/**
	 * Parses a private key JSON Web Token (JWT) authentication from the 
	 * specified {@code application/x-www-form-urlencoded} encoded 
	 * parameters string.
	 *
	 * @param paramsString The parameters string to parse. The private key
	 *                     JSON Web Token (JWT) parameters must be keyed 
	 *                     under "client_assertion" and 
	 *                     "client_assertion_type". The string must not be 
	 *                     {@code null}.
	 *
	 * @return The private key JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters string couldn't be parsed to
	 *                        a valid private key JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static PrivateKeyJWT parse(final String paramsString)
		throws ParseException {
		
		Map<String,String> params = URLUtils.parseParameters(paramsString);
		
		return parse(params);
	}
	
	
	/**
	 * Parses the specified HTTP POST request for a private key JSON Web 
	 * Token (JWT) authentication.
	 *
	 * @param httpRequest The HTTP POST request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    {@code application/x-www-form-urlencoded} encoded 
	 *                    parameters string in the entity body. The private 
	 *                    key JSON Web Token (JWT) parameters must be 
	 *                    keyed under "client_assertion" and 
	 *                    "client_assertion_type".
	 *
	 * @return The private key JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the HTTP request header couldn't be parsed
	 *                        to a valid private key JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static PrivateKeyJWT parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getQueryParameters());
	}
}
