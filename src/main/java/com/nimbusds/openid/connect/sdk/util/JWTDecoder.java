package com.nimbusds.openid.connect.sdk.util;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;


/**
 * Decoder of JSON Web Tokens (JWTs). Handles plain JWTs as well as JWTs
 * secured by means of JSON Web Signature (JWS) and / or JSON Web Encryption 
 * (JWE). If the object is secured performs the necessary JWS validation and /
 * or JWE decryption.
 *
 * @author Vladimir Dzhuvinov
 */
public interface JWTDecoder {


	/**
	 * Decodes a JWT object, then applies JWS signature validation and / or
	 * JWE decryption if the token is secured.
	 *
	 * @param jwt The JWT to decode. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws JOSEException If decoding, JWS validation and / or JWE
	 *                       decryption of the JWT failed.
	 */
	public ReadOnlyJWTClaimsSet decodeJWT(final JWT jwt)
		throws JOSEException;
}
