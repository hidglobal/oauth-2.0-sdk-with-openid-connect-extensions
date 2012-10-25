package com.nimbusds.openid.connect.sdk.util;


import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.Payload;


/**
 * Decoder of Javascript Object Signing and Encryption (JOSE) objects. Handles 
 * plaintext, JWS and JWE secured objects. If the object is secured performs 
 * Java Web Signature (JWS) validation and/or Java Web Encryption (JWE) 
 * decryption.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-17)
 */
public interface JOSEObjectDecoder {


	/**
	 * Decodes a JOSE object by applying JWS signature validation and/or JWE 
	 * decryption if the object is secured.
	 *
	 * @param joseObject The JOSE object. Must not be {@code null}.
	 *
	 * @return The decoded JOSE object payload.
	 *
	 * @throws JOSEException If decoding, signature validation and/or JWE
	 *                       decryption of the JOSE object failed.
	 */
	public Payload decodeJOSEObject(final JOSEObject joseObject)
		throws JOSEException;
}
