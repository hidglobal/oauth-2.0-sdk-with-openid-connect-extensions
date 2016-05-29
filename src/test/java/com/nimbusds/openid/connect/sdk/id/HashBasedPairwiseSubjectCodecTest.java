package com.nimbusds.openid.connect.sdk.id;


import java.security.SecureRandom;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


public class HashBasedPairwiseSubjectCodecTest extends TestCase {
	

	public void testAlgConstant() {
		assertEquals("SHA-256", HashBasedPairwiseSubjectCodec.HASH_ALGORITHM);
	}


	public void testEncode() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());

		SectorIdentifier sectorID = new SectorIdentifier("example.com");
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);
		assertEquals(256, new Base64URL(pairwiseSubject.getValue()).decode().length * 8);
	}


	public void testConstructorConsistency() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());

		SectorIdentifier sectorID = new SectorIdentifier("example.com");
		Subject localSubject = new Subject("alice");

		Subject s1 = codec.encode(sectorID, localSubject);

		codec = new HashBasedPairwiseSubjectCodec(Base64URL.encode(salt));
		Subject s2 = codec.encode(sectorID, localSubject);

		assertEquals(s1, s2);
	}


	public void testEncodeWithProvider() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());

		codec.setProvider(BouncyCastleProviderSingleton.getInstance());
		assertEquals(BouncyCastleProviderSingleton.getInstance(), codec.getProvider());

		SectorIdentifier sectorID = new SectorIdentifier("example.com");
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);
		assertEquals(256, new Base64URL(pairwiseSubject.getValue()).decode().length * 8);
	}


	public void testDecode()
		throws InvalidPairwiseSubjectException {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);

		try {
			codec.decode(new Subject("xyz"));
			fail();
		} catch (UnsupportedOperationException e) {
			assertEquals("Pairwise subject decoding is not supported", e.getMessage());
		}
	}
}
