package com.nimbusds.openid.connect.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JOSEException;


/**
 * Decoder of JOSE-encoded OpenID Connect request objects. If the request
 * object is protected performs Java Web Signature (JWS) validation and/or 
 * Java Web Encryption (JWE) decryption.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-11)
 */
public interface RequestObjectDecoder {


	/**
	 * Decodes a JOSE-encoded OpenID Connect request object by applying
	 * JWS signature validation and/or JWE decryption if the object is
	 * protected.
	 *
	 * @param requestObject The OpenID Connect request object. Must not be 
	 *                      {@code null}.
	 *
	 * @return The decoded JSON object payload representing the OpenID 
	 *         Connect request object.
	 *
	 * @throws JOSEException If decoding, signature validation and/or JWE
	 *                       decryption of the JOSE object failed.
	 */
	public JSONObject decodeRequestObject(final JOSEObject requestObject)
		throws JOSEException;
}
