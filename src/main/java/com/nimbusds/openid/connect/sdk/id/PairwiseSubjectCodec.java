package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;
import java.nio.charset.Charset;
import java.security.Provider;

import com.nimbusds.oauth2.sdk.id.Subject;
import net.jcip.annotations.ThreadSafe;
import org.apache.commons.lang3.tuple.Pair;


/**
 * Encoder and decoder of pairwise subject identifiers. The encoder algorithms
 * must be deterministic, to ensure a given set of inputs always produces an
 * identical pairwise subject identifier.
 *
 * <p>Decoding pairwise subject identifiers is optional, and is implemented by
 * algorithms that supported reversal (typically with encryption-based codecs).
 * Hash-based codecs don't support reversal.
 *
 * <p>Codec implementations thread-safe.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
@ThreadSafe
public abstract class PairwiseSubjectCodec {


	/**
	 * The charset (UTF-8) for string to byte conversions.
	 */
	public static final Charset CHARSET = Charset.forName("UTF-8");


	/**
	 * The salt.
	 */
	private final byte[] salt;


	/**
	 * The security provider.
	 */
	private Provider provider;


	/**
	 * Creates a new codec for pairwise subject identifiers.
	 *
	 * @param salt The salt, {@code null} if not required.
	 */
	public PairwiseSubjectCodec(byte[] salt) {

		this.salt = salt;
	}


	/**
	 * Returns the salt.
	 *
	 * @return The salt, {@code null} if not required.
	 */
	public byte[] getSalt() {
		return salt;
	}


	/**
	 * Gets the security provider for cryptographic operations.
	 *
	 * @return The security provider, {@code null} if not specified
	 *         (implies the default one).
	 */
	public Provider getProvider() {
		return provider;
	}


	/**
	 * Sets the security provider for cryptographic operations.
	 *
	 * @param provider The security provider, {@code null} if not specified
	 *                 (implies the default one).
	 */
	public void setProvider(Provider provider) {
		this.provider = provider;
	}


	/**
	 * Encodes a new pairwise subject identifier from the specified sector
	 * identifier URI and local subject.
	 *
	 * @param sectorURI The sector identifier URI. Its scheme should be
	 *                  "https", must include a host portion and must not
	 *                  be {@code null}.
	 * @param localSub  The local subject identifier. Must not be
	 *                  {@code null}.
	 *
	 * @return The pairwise subject identifier.
	 */
	public Subject encode(final URI sectorURI, final Subject localSub) {

		return encode(new SectorID(sectorURI), localSub);
	}


	/**
	 * Encodes a new pairwise subject identifier from the specified sector
	 * identifier and local subject.
	 *
	 * @param sectorID The sector identifier. Must not be
	 *                         {@code null}.
	 * @param localSub         The local subject identifier. Must not be
	 *                         {@code null}.
	 *
	 * @return The pairwise subject identifier.
	 */
	public abstract Subject encode(final SectorID sectorID, final Subject localSub);


	/**
	 * Decodes the specified pairwise subject identifier to produce the
	 * matching sector identifier and local subject. Throws a
	 * {@link UnsupportedOperationException}. Codecs that support pairwise
	 * subject identifier reversal should override this method.
	 *
	 * @param pairwiseSubject The pairwise subject identifier. Must be
	 *                        valid and not {@code null}.
	 *
	 * @return The matching sector identifier and local subject.
	 *
	 * @throws InvalidPairwiseSubjectException If the pairwise subject is
	 *                                         invalid.
	 */
	public Pair<SectorID,Subject> decode(final Subject pairwiseSubject)
		throws InvalidPairwiseSubjectException {

		throw new UnsupportedOperationException("Pairwise subject decoding is not supported");
	}
}
