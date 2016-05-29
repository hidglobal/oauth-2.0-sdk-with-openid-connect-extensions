package com.nimbusds.openid.connect.sdk.id;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.Subject;
import net.jcip.annotations.ThreadSafe;


/**
 * SHA-256 based encoder of pairwise subject identifiers. Reversal is not
 * supported.
 *
 * <p>Algorithm:
 *
 * <pre>
 * sub = SHA-256 ( sector_id || local_sub || salt )
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
@ThreadSafe
public class HashBasedPairwiseSubjectCodec extends PairwiseSubjectCodec {


	/**
	 * The hashing algorithm.
	 */
	public static final String HASH_ALGORITHM = "SHA-256";


	/**
	 * Creates a new hash-based codec for pairwise subject identifiers.
	 *
	 * @param salt The salt, must not be {@code null}.
	 */
	public HashBasedPairwiseSubjectCodec(final byte[] salt) {
		super(salt);
		if (salt == null) {
			throw new IllegalArgumentException("The salt must not be null");
		}
	}


	/**
	 * Creates a new hash-based codec for pairwise subject identifiers.
	 *
	 * @param salt The salt, must not be {@code null}.
	 */
	public HashBasedPairwiseSubjectCodec(final Base64URL salt) {
		super(salt.decode());
	}


	@Override
	public Subject encode(final SectorIdentifier sectorIdentifier, final Subject localSub) {

		MessageDigest sha256;
		try {
			if (getProvider() != null) {
				sha256 = MessageDigest.getInstance(HASH_ALGORITHM, getProvider());
			} else {
				sha256 = MessageDigest.getInstance(HASH_ALGORITHM);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage(), e);
		}

		sha256.update(sectorIdentifier.getValue().getBytes(CHARSET));
		sha256.update(localSub.getValue().getBytes(CHARSET));
		byte[] hash = sha256.digest(getSalt());

		return new Subject(Base64URL.encode(hash).toString());
	}
}
