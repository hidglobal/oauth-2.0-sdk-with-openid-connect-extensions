package com.nimbusds.openid.connect.sdk.id;


import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

import com.nimbusds.oauth2.sdk.id.Subject;


/**
 * SHA-256 based generator of pairwise subject identifiers.
 *
 * <p>Algorithm:
 *
 * <pre>
 * sub = SHA-256 ( sector_identifier | local_account_id | salt )
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
public class HashingSubjectIdentifierGenerator extends PairwiseSubjectIdentifierGenerator {


	/**
	 * The hashing algorithm.
	 */
	public static final String HASH_ALGORITHM = "SHA-256";


	/**
	 * UTF-8 is the charset for byte to and from string conversions.
	 */
	private final Charset charset;


	/**
	 * The salt.
	 */
	private final byte[] salt;


	/**
	 * Creates a new SHA-256 based generator of pairwise subject
	 * identifiers.
	 *
	 * @param salt The string to use for the salt. Must not be empty, blank
	 *             or {@code null}.
	 *
	 * @throws NoSuchAlgorithmException If SHA-256 isn't supported by the
	 *                                  underlying JVM.
	 */
	public HashingSubjectIdentifierGenerator(final String salt)
		throws NoSuchAlgorithmException {

		charset = Charset.forName("UTF-8");

		if (salt == null)
			throw new IllegalArgumentException("The salt must not be null");

		if (salt.trim().isEmpty())
			throw new IllegalArgumentException("The salt string must not be blank or empty");

		this.salt = salt.getBytes(charset);

		MessageDigest.getInstance(HASH_ALGORITHM);
	}


	/**
	 * Returns the salt bytes.
	 *
	 * @return The salt bytes.
	 */
	public byte[] saltBytes() {

		return salt;
	}


	@Override
	public Subject generate(final String sectorIdentifier, final Subject localSub) {

		MessageDigest sha256;

		try {
			sha256 = MessageDigest.getInstance(HASH_ALGORITHM);

		} catch (NoSuchAlgorithmException e) {

			throw new IllegalStateException(e.getMessage(), e);
		}

		sha256.update(sectorIdentifier.getBytes(charset));
		sha256.update(localSub.getValue().getBytes(charset));
		byte[] hash = sha256.digest(salt);

		return new Subject(Base64.encodeBase64URLSafeString(hash));
	}
}
