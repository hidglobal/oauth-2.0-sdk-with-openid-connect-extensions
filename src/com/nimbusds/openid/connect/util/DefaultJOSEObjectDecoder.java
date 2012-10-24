package com.nimbusds.openid.connect.util;


import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeaderFilter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeaderFilter;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainObject;


/**
 * The default decoder of JOSE objects. This class is thread-safe.
 *
 * <p>Supports:
 *
 * <ul>
 *     <li>Plaintext JOSE objects.
 *     <li>JWS-signed objects.
 *     <li>JWE-encrypted objects.
 * </ul>
 *
 * <p>Not supported: JWS-signed and then JWE-encrypted (nested) objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-24)
 */
public class DefaultJOSEObjectDecoder implements JOSEObjectDecoder {


	/**
	 * Thread-safe map of configured JWS verifiers.
	 */
	private final Map<JWSAlgorithm,JWSVerifier> jwsVerifiers = new Hashtable<JWSAlgorithm,JWSVerifier>();
	
	
	/**
	 * Thread-safe map of configured JWE decrypters.
	 */
	private final Map<JWEAlgorithm,JWEDecrypter> jweDecrypters = new Hashtable<JWEAlgorithm,JWEDecrypter>();
	
	
	/**
	 * Creates a new decoder of JOSE objects. It must then be configured by 
	 * adding one ore more JWS verifiers and/or JWE decrypters.
	 */
	public DefaultJOSEObjectDecoder() {
	
		// Nothing to do
	}
	
	
	/**
	 * Adds the specified JWS verifier for decoding signed JOSE objects.
	 * The JWS algorithms accepted by the verifier should match the ones 
	 * used to secure the expected JOSE objects.
	 *
	 * @param verifier The JWS verifier to add. Must be ready to verify
	 *                 signed JOSE objects and not {@code null}.
	 */
	public void addJWSVerifier(final JWSVerifier verifier) {
	
		JWSHeaderFilter filter = verifier.getJWSHeaderFilter();
		 
		for (JWSAlgorithm alg: filter.getAcceptedAlgorithms())
			jwsVerifiers.put(alg, verifier);
	}
	
	
	/**
	 * Gets the JWS verifiers.
	 *
	 * @return The JWS verifiers, empty collection if none.
	 */
	public Collection<JWSVerifier> getJWSVerifiers() {
	
		return jwsVerifiers.values();
	}
	
	
	/**
	 * Adds the specified JWE decrypter for decoding encrypted JOSE objects.
	 * The JWE algorithms accepted by the decrypter should match the ones
	 * used to secure the expected JOSE objects.
	 *
	 * @param decrypter The JWE decrypter to add. Must be ready to decrypt
	 *                  encrypted JOSE objects and not {@code null}.
	 */
	public void addJWEDecrypter(final JWEDecrypter decrypter) {
	
		JWEHeaderFilter filter = decrypter.getJWEHeaderFilter();
		
		for (JWEAlgorithm alg: filter.getAcceptedAlgorithms())
			jweDecrypters.put(alg, decrypter);
	}
	
	
	/**
	 * Gets the JWE decrypters.
	 *
	 * @return The JWE decrypters, empty collection if none.
	 */
	public Collection<JWEDecrypter> getJWEDecrypters() {
	
		return jweDecrypters.values();
	}
	
	
	/**
	 * Verifiers a JWS object signature by calling the matching verifier 
	 * for its algorithm.
	 *
	 * @param jwsObject The JWS object to verify. Must not be {@code null}.
	 *
	 * @return The JWS payload.
	 *
	 * @throws JOSEException If no matching JWS verifier was found, the 
	 *                       signature is bad or verification failed.
	 */
	private Payload verify(final JWSObject jwsObject)
		throws JOSEException {
		
		JWSAlgorithm alg = jwsObject.getHeader().getAlgorithm();
		
		JWSVerifier verifier = jwsVerifiers.get(alg);
		
		if (verifier == null)
			throw new JOSEException("Unsupported JWS algorithm: " + alg);
		
		boolean verified = jwsObject.verify(verifier);
		
		if (! verified)
			throw new JOSEException("Bad JWS signature");
		
		return jwsObject.getPayload();
	}
	
	
	/**
	 * Decrypts a JWE object by calling the matching decrypter for its
	 * algorithm.
	 *
	 * @param jweObject The JWE object to decrypt. Must not be {@code null}.
	 *
	 * @return The JWE cleartext.
	 *
	 * @throws JOSEException If not matching JWE decrypter was found or if
	 *                       decryption failed.
	 */
	private Payload decrypt(final JWEObject jweObject)
		throws JOSEException {
		
		JWEAlgorithm alg = jweObject.getHeader().getAlgorithm();
		
		JWEDecrypter decrypter = jweDecrypters.get(alg);
		
		if (decrypter == null)
			throw new JOSEException("Unsupported JWE algorithm: " + alg);
		
		jweObject.decrypt(decrypter);
		
		return jweObject.getPayload();
	}


	@Override
	public Payload decodeJOSEObject(final JOSEObject joseObject)
		throws JOSEException {
		
		if (joseObject instanceof PlainObject) {
		
			PlainObject plainObject = (PlainObject)joseObject;
			
			return plainObject.getPayload();
		}
		else if (joseObject instanceof JWSObject) {
		
			JWSObject jwsObject = (JWSObject)joseObject;
			
			return verify(jwsObject);
		}
		else if (joseObject instanceof JWEObject) {
		
			JWEObject jweObject = (JWEObject)joseObject;
			
			return decrypt(jweObject);
		}
		else {
		
			throw new JOSEException("Unexpected JOSE object type: " + joseObject.getClass());
		}
	}
}
