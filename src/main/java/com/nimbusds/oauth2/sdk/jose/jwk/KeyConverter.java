package com.nimbusds.oauth2.sdk.jose.jwk;


import java.security.Key;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;


/**
 * Key converter.
 */
public class KeyConverter {
	

	/**
	 * Converts the specified list of JSON Web Keys (JWK) their standard
	 * Java class representation. Only RSA, EC and OCT keys are converted.
	 * Key conversion exceptions are silently ignored.
	 *
	 * @param jwkList The JWK list. May be {@code null}.
	 *
	 * @return The converted keys, empty set if none.
	 */
	public static List<Key> toJavaKeys(final List<JWK> jwkList) {

		if (jwkList == null) {
			return Collections.emptyList();
		}

		List<Key> out = new LinkedList<>();
		for (JWK jwk: jwkList) {
			try {
				if (jwk instanceof RSAKey) {
					out.add(((RSAKey) jwk).toRSAPublicKey());
				} else if (jwk instanceof ECKey) {
					out.add(((ECKey) jwk).toECPublicKey());
				} else if (jwk instanceof OctetSequenceKey) {
					out.add(((OctetSequenceKey) jwk).toSecretKey());
				}
			} catch (JOSEException e) {
				// ignore and continue
			}
		}
		return out;
	}
}
