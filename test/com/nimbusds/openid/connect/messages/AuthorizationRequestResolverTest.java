package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.util.DefaultJOSEObjectDecoder;
import com.nimbusds.openid.connect.util.DefaultJOSEObjectRetriever;
import com.nimbusds.openid.connect.util.JOSEObjectDecoder;
import com.nimbusds.openid.connect.util.JOSEObjectRetriever;


/**
 * Tests the authorisation request resolver.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-24)
 */
public class AuthorizationRequestResolverTest extends TestCase {


	private AuthorizationRequestResolver getResolver() {

		return null;

	}


	public void testConstructorMinimal() {

		JOSEObjectDecoder decoder = new DefaultJOSEObjectDecoder();

		AuthorizationRequestResolver resolver = 
			new AuthorizationRequestResolver(decoder);

		assertNotNull(resolver.getJOSEObjectRetriever());
		assertNotNull(resolver.getJOSEObjectDecoder());
	}


	public void testConstructorFull() {

		JOSEObjectRetriever retriever = new DefaultJOSEObjectRetriever();
		JOSEObjectDecoder decoder = new DefaultJOSEObjectDecoder();

		AuthorizationRequestResolver resolver = 
			new AuthorizationRequestResolver(retriever, decoder);

		assertNotNull(resolver.getJOSEObjectRetriever());
		assertNotNull(resolver.getJOSEObjectDecoder());
	}

}