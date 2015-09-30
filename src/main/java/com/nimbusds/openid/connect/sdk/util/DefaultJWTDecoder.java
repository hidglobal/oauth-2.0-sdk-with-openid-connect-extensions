package com.nimbusds.openid.connect.sdk.util;


import java.text.ParseException;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;


/**
 * The default decoder of JSON Web Tokens (JWTs).
 *
 * <p>Supports:
 *
 * <ul>
 *     <li>Plaintext JWTs.
 *     <li>JWS-signed JWTs.
 *     <li>JWE-encrypted JWTs.
 * </ul>
 *
 * <p>Not supported: JWS-signed and then JWE-encrypted (nested) objects.
 */
@ThreadSafe
public class DefaultJWTDecoder implements JWTDecoder {


	/**
	 * Thread-safe map of available JWS verifiers.
	 */
	private final Map<JWSAlgorithm,JWSVerifier> jwsVerifiers = 
		new Hashtable<>();
	
	
	/**
	 * Thread-safe map of available JWE decrypters.
	 */
	private final Map<JWEAlgorithm,JWEDecrypter> jweDecrypters = 
		new Hashtable<>();
	
	
	/**
	 * Creates a new decoder of JSON Web Tokens (JWTs). The decoder must 
	 * then be supplied with one or more configured JWS verifiers and / or 
	 * JWE decrypters.
	 */
	public DefaultJWTDecoder() {
	
		// Nothing to do
	}
	
	
	/**
	 * Adds the specified JWS verifier for decoding signed JWTs. The JWS 
	 * algorithms accepted by the verifier should match the ones used to 
	 * secure the expected JWTs.
	 *
	 * @param verifier The JWS verifier to add. Must be ready to verify
	 *                 signed JWTs and not {@code null}.
	 */
	public void addJWSVerifier(final JWSVerifier verifier) {
	
		for (JWSAlgorithm alg: verifier.supportedJWSAlgorithms()) {

			jwsVerifiers.put(alg, verifier);
		}
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
	 * Adds the specified JWE decrypter for decoding encrypted JWTs. The
	 * JWE algorithms accepted by the decrypter should match the ones
	 * used to secure the expected JWTs.
	 *
	 * @param decrypter The JWE decrypter to add. Must be ready to decrypt
	 *                  encrypted JWTs and not {@code null}.
	 */
	public void addJWEDecrypter(final JWEDecrypter decrypter) {
	
		for (JWEAlgorithm alg: decrypter.supportedJWEAlgorithms()) {

			jweDecrypters.put(alg, decrypter);
		}
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
	 * Verifies a signed JWT by calling the matching verifier for its JWS
	 * algorithm.
	 *
	 * @param signedJWT The signed JWT to verify. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws JOSEException  If no matching JWS verifier was found, the 
	 *                        signature is bad or verification failed.
	 * @throws ParseException If parsing of the JWT claims set failed.
	 */
	private JWTClaimsSet verify(final SignedJWT signedJWT)
		throws JOSEException, ParseException {
		
		JWSAlgorithm alg = signedJWT.getHeader().getAlgorithm();
		
		JWSVerifier verifier = jwsVerifiers.get(alg);
		
		if (verifier == null) {

			throw new JOSEException("Unsupported JWS algorithm: " + alg);
		}
			
		
		boolean verified;

		try {
			verified = signedJWT.verify(verifier);

		} catch (IllegalStateException e) {

			throw new JOSEException(e.getMessage(), e);
		}
		
		if (! verified) {

			throw new JOSEException("Bad JWS signature");
		}
		
		return signedJWT.getJWTClaimsSet();
	}
	
	
	/**
	 * Decrypts an encrypted JWT by calling the matching decrypter for its
	 * JWE algorithm and encryption method.
	 *
	 * @param encryptedJWT The encrypted JWT to decrypt. Must not be 
	 *                     {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws JOSEException  If no matching JWE decrypter was found or if
	 *                        decryption failed.
	 * @throws ParseException If parsing of the JWT claims set failed.
	 */
	private JWTClaimsSet decrypt(final EncryptedJWT encryptedJWT)
		throws JOSEException, ParseException {
		
		JWEAlgorithm alg = encryptedJWT.getHeader().getAlgorithm();
		
		JWEDecrypter decrypter = jweDecrypters.get(alg);
		
		if (decrypter == null) {

			throw new JOSEException("Unsupported JWE algorithm: " + alg);
		}
		
		
		try {
			encryptedJWT.decrypt(decrypter);

		} catch (IllegalStateException e) {

			throw new JOSEException(e.getMessage(), e);
		}
		
		return encryptedJWT.getJWTClaimsSet();
	}


	@Override
	public JWTClaimsSet decodeJWT(final JWT jwt)
		throws JOSEException, ParseException {
		
		if (jwt instanceof PlainJWT) {
		
			PlainJWT plainJWT = (PlainJWT)jwt;
			
			return plainJWT.getJWTClaimsSet();
		
		} else if (jwt instanceof SignedJWT) {
		
			SignedJWT signedJWT = (SignedJWT)jwt;
			
			return verify(signedJWT);

		} else if (jwt instanceof EncryptedJWT) {
		
			EncryptedJWT encryptedJWT = (EncryptedJWT)jwt;
			
			return decrypt(encryptedJWT);
			
		} else {
		
			throw new JOSEException("Unexpected JWT type: " + jwt.getClass());
		}
	}
}
