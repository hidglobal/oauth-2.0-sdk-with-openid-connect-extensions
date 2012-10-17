package com.nimbusds.openid.connect.messages;


import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import net.minidev.json.JSONObject;

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
 * The default decoder of JOSE-encoded OpenID Connect request objects. This 
 * class is thread-safe.
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
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-17)
 */
public class DefaultRequestObjectDecoder implements RequestObjectDecoder {


	/**
	 * Thread-safe map of configured JWS validators.
	 */
	private final Map<JWSAlgorithm,JWSValidator> jwsValidators = new Hashtable<JWSAlgorithm,JWSValidator>();
	
	
	/**
	 * Thread-safe map of configured JWE decrypters.
	 */
	private final Map<JWEAlgorithm,JWEDecrypter> jweDecrypters = new Hashtable<JWEAlgorithm,JWEDecrypter>();
	
	
	/**
	 * Creates a new decoder of JOSE-encoded OpenID Connect request objects.
	 * It must be configured by adding one ore more JWS validators and/or
	 * JWE decrypters.
	 */
	public DefaultRequestObjectDecoder() {
	
		// Nothing to do
	}
	
	
	/**
	 * Adds the specified JWS validator for decoding signed OpenID Connect
	 * request objects. Its accepted JWS algorithms should match the ones
	 * used to secure the expected OpenID Connect request objects.
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
	 * Adds the specified JWE decrypter for decoding encrypted OpenID 
	 * Connect request objects. Its accepted JWE algorithms should match the
	 * ones used to secure the expected OpenID Connect request objects.
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
	public JSONObject decodeRequestObject(final JOSEObject requestObject)
		throws JOSEException {
		
		Payload payload = null;
		
		if (requestObject instanceof PlainObject) {
		
			PlainObject plainObject = (PlainObject)requestObject;
			
			payload = plainObject.getPayload();
		}
		else if (requestObject instanceof JWSObject) {
		
			JWSObject jwsObject = (JWSObject)requestObject;
		}
		else if (requestObject instanceof JWEObject) {
		
			JWEObject jweObject = (JWEObject)requestObject;
		}
		else {
		
			throw new JOSEException("Unexpected JOSE object type: " + requestObject.getClass());
		}
			
		
		JSONObject jsonObject = payload.toJSONObject();
		
		if (jsonObject == null)
			throw new JOSEException("The decoded JOSE object payload is not a JSON object");
		
		return jsonObject;
	}
}
