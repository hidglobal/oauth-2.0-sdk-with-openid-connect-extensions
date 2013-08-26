package com.nimbusds.openid.connect.sdk.id;


import java.nio.charset.Charset;

import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


/**
 * Tests the SHA-256 based generator of pairwise subject identifiers.
 *
 * @author Vladimir Dzhuvinov
 */
public class HashingSubjectIdentifierGeneratorTest extends TestCase {


	public void testRun()
		throws Exception {

		String salt = "Gps4_";

		HashingSubjectIdentifierGenerator gen = new HashingSubjectIdentifierGenerator(salt);

		assertEquals(salt, new String(gen.saltBytes(), Charset.forName("UTF-8")));

		String sectorID = "example.com";
		Subject localSubject = new Subject("alice");

		Subject pairWiseSubject = gen.generate(sectorID, localSubject);

		System.out.println("Pairwise subject: " + pairWiseSubject);

		assertEquals("Consistency check", pairWiseSubject.toString(), gen.generate(sectorID, localSubject));
	}
}
