package com.nimbusds.openid.connect.sdk.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.util.DefaultJOSEObjectDecoder;
import com.nimbusds.openid.connect.sdk.util.DefaultJOSEObjectRetriever;
import com.nimbusds.openid.connect.sdk.util.JOSEObjectDecoder;
import com.nimbusds.openid.connect.sdk.util.JOSEObjectRetriever;


/**
 * Tests the authorisation request resolver.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-17)
 */
public class AuthorizationRequestResolverTest extends TestCase {


	private AuthorizationRequestResolver getResolver() {

		JOSEObjectDecoder decoder = new DefaultJOSEObjectDecoder();

		AuthorizationRequestResolver resolver = 
			new AuthorizationRequestResolver(decoder);

		return resolver;
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


	public void testSimpleRequest()
		throws Exception {

		AuthorizationRequest request = AuthorizationRequest.parse(TestVectors.AuthorizationRequest.SIMPLE_REQUEST);

		AuthorizationRequestResolver resolver = getResolver();

		ResolvedAuthorizationRequest resolvedRequest = resolver.resolve(request);

		// response_type
		ResponseTypeSet rts = resolvedRequest.getResponseTypeSet();
		assertTrue(rts.impliesCodeFlow());
		assertEquals(2, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		assertTrue(rts.contains(ResponseType.ID_TOKEN));

		// client_id
		assertEquals("s6BhdRkqt3", resolvedRequest.getClientID().getClaimValue());

		// redirect_uri
		assertEquals("https://client.example.org/cb", resolvedRequest.getRedirectURI().toString());

		// scope
		

		// nonce
		assertEquals("n-0S6_WzA2Mj", resolvedRequest.getNonce().toString());

		// state
		assertEquals("af0ifjsldkj", resolvedRequest.getState().toString());

		// ID token claims
		IDTokenClaimsRequest idToken = resolvedRequest.getIDTokenClaimsRequest();

		assertNull(idToken.getRequiredUserID());
		assertNull(idToken.getRequiredACRs());
		assertEquals(-1, idToken.getRequiredMaxAge());


		// UserInfo claims
		UserInfoClaimsRequest userInfo = resolvedRequest.getUserInfoClaimsRequest();

		// defaults

		assertEquals(Display.PAGE, resolvedRequest.getDisplay());

		assertNull(resolvedRequest.getPrompt());

		assertNull(resolvedRequest.getIDTokenHint());

	}
}
