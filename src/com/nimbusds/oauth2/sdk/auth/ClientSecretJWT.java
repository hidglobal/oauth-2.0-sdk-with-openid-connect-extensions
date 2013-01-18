package com.nimbusds.oauth2.sdk.auth;


import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.id.ClientID;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Client secret JWT authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT}. This class is 
 * immutable.
 *
 * <p>Supported signature JSON Web Algorithms (JWAs) by this implementation:
 *
 * <ul>
 *     <li>HS256
 *     <li>HS384
 *     <li>HS512
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 (draft-ietf-oauth-assertions-06)
 *     <li>JSON Web Token (JWT) Bearer Token Profiles for OAuth 2.0 
 *         (draft-ietf-oauth-jwt-bearer-04).
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-18)
 */
@Immutable
public final class ClientSecretJWT extends JWTAuthentication {


	/**
	 * Gets the set of supported signature JSON Web Algorithms (JWAs) by 
	 * this implementation of client secret JSON Web Token (JWT) 
	 * authentication.
	 *
	 * @return The set of supported JSON Web Algorithms (JWAs).
	 */
	public static Set<JWSAlgorithm> getSupportedJWAs() {
	
		Set<JWSAlgorithm> supported = new HashSet<JWSAlgorithm>();
		
		supported.add(JWSAlgorithm.HS256);
		supported.add(JWSAlgorithm.HS384);
		supported.add(JWSAlgorithm.HS512);
		
		return Collections.unmodifiableSet(supported);
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
	
		super(ClientAuthenticationMethod.CLIENT_SECRET_JWT, clientAssertion, clientID);
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
	 *                        client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final Map<String,String> params)
		throws ParseException {
	
		JWTAuthentication.ensureClientAssertionType(params);
		
		SignedJWT clientAssertion = JWTAuthentication.parseClientAssertion(params);
		
		ClientID clientID = JWTAuthentication.parseClientID(params);
		
		JWSAlgorithm alg = clientAssertion.getHeader().getAlgorithm();
		
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
	 * @throws ParseException If the parameters string couldn't be parsed 
	 *                        to a client secret JSON Web Token (JWT) 
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
	 *                        to a client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getQueryParameters());
	}
}
