package com.nimbusds.openid.connect.sdk.id;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.Subject;
import net.jcip.annotations.ThreadSafe;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;


/**
 * AES/CBC/PKCS5Padding based encoder / decoder of pairwise subject
 * identifiers. The salt is used as the IV. Reversal is supported.
 *
 * <p>The plain text is formatted as follows ('\' as delimiter):
 *
 * <pre>
 * sector_id|local_sub
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
@ThreadSafe
public class AESBasedPairwiseSubjectCodec extends PairwiseSubjectCodec {


	/**
	 * The AES key.
	 */
	private final SecretKey aesKey;


	/**
	 * Creates a new AES-based codec for pairwise subject identifiers.
	 *
	 * @param aesKey The AES key. Must not be {@code null}.
	 * @param salt   The salt. Must not be {@code null}.
	 */
	public AESBasedPairwiseSubjectCodec(final SecretKey aesKey, final byte[] salt) {
		super(salt);
		if (salt == null) {
			throw new IllegalArgumentException("The salt must not be null");
		}
		if (aesKey == null) {
			throw new IllegalArgumentException("The AES key must not be null");
		}
		this.aesKey = aesKey;
	}


	/**
	 * Returns the AES key.
	 *
	 * @return The key.
	 */
	public SecretKey getAESKey() {
		return aesKey;
	}


	/**
	 * Creates a new AES/CBC/PKCS5Padding cipher using the configured
	 * JCE provider and salt.
	 *
	 * @param mode The cipher mode.
	 *
	 * @return The cipher.
	 */
	private Cipher createCipher(final int mode) {

		Cipher aesCipher;

		try {
			if (getProvider() != null) {
				aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", getProvider());
			} else {
				aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			}

			aesCipher.init(mode, aesKey, new IvParameterSpec(getSalt()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		return aesCipher;
	}


	@Override
	public Subject encode(final SectorID sectorID, final Subject localSub) {

		// Join parameters, delimited by '\'
		byte[] plainText = (sectorID.getValue().replace("|", "\\|") + '|' + localSub.getValue().replace("|", "\\|")).getBytes(CHARSET);
		byte[] cipherText;
		try {
			cipherText = createCipher(Cipher.ENCRYPT_MODE).doFinal(plainText);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		return new Subject(Base64URL.encode(cipherText).toString());
	}


	@Override
	public Pair<SectorID, Subject> decode(final Subject pairwiseSubject)
		throws InvalidPairwiseSubjectException {

		byte[] cipherText = new Base64URL(pairwiseSubject.getValue()).decode();

		Cipher aesCipher = createCipher(Cipher.DECRYPT_MODE);

		byte[] plainText;
		try {
			plainText = aesCipher.doFinal(cipherText);
		} catch (Exception e) {
			throw new InvalidPairwiseSubjectException("Decryption failed: " + e.getMessage(), e);
		}

		String parts[] = new String(plainText, CHARSET).split("(?<!\\\\)\\|");

		// Unescape delimiter
		for (int i=0; i<parts.length; i++) {
			parts[i] = parts[i].replace("\\|", "|");
		}

		// Check format
		if (parts.length != 2) {
			throw new InvalidPairwiseSubjectException("Invalid format: Unexpected number of tokens: " + parts.length);
		}

		return new ImmutablePair<>(new SectorID(parts[0]), new Subject(parts[1]));
	}
}
