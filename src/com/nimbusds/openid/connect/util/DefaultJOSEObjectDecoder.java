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
import com.nimbusds.jose.JWSValidator;
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
 * @version $version$ (2012-10-17)
 */
public class DefaultJOSEObjectDecoder implements JOSEObjectDecoder {


	/**
	 * Thread-safe map of configured JWS validators.
	 */
	private final Map<JWSAlgorithm,JWSValidator> jwsValidators = new Hashtable<JWSAlgorithm,JWSValidator>();
	
	
	/**
	 * Thread-safe map of configured JWE decrypters.
	 */
	private final Map<JWEAlgorithm,JWEDecrypter> jweDecrypters = new Hashtable<JWEAlgorithm,JWEDecrypter>();
	
	
	/**
	 * Creates a new decoder of JOSE objects. It must then be configured by 
	 * adding one ore more JWS validators and/or JWE decrypters.
	 */
	public DefaultJOSEObjectDecoder() {
	
		// Nothing to do
	}
	
	
	/**
	 * Adds the specified JWS validator for decoding signed JOSE objects.
	 * The JWS algorithms accepted by the validator should match the ones 
	 * used to secure the expected JOSE objects.
	 *
	 * @param validator The JWS validator to add. Must be ready to validate
	 *                  signed JOSE objects and not {@code null}.
	 */
	public void addJWSValidator(final JWSValidator validator) {
	
		JWSHeaderFilter filter = validator.getJWSHeaderFilter();
		 
		for (JWSAlgorithm alg: filter.getAcceptedAlgorithms())
			jwsValidators.put(alg, validator);
	}
	
	
	/**
	 * Gets the JWS validators.
	 *
	 * @return The JWS validators, empty collection if none.
	 */
	public Collection<JWSValidator> getJWSValidators() {
	
		return jwsValidators.values();
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
	 * Validates a JWS object by calling the matching validator for its
	 * algorithm.
	 *
	 * @param jwsObject The JWS object to validate. Must not be {@code null}.
	 *
	 * @return The JWS payload.
	 *
	 * @throws JOSEException If no matching JWS validator was found, the 
	 *                       signature is invalid or validation failed.
	 */
	private Payload validate(final JWSObject jwsObject)
		throws JOSEException {
		
		JWSAlgorithm alg = jwsObject.getHeader().getAlgorithm();
		
		JWSValidator validator = jwsValidators.get(alg);
		
		if (validator == null)
			throw new JOSEException("Unsupported JWS algorithm: " + alg);
		
		boolean valid = jwsObject.validate(validator);
		
		if (! valid)
			throw new JOSEException("Invalid JWS signature");
		
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
	 * @throws JOSEException If not matching JWE validator was found or if
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
			
			return validate(jwsObject);
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
