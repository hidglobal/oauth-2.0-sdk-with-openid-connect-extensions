package com.nimbusds.oauth2.sdk.auth.verifier;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.client.ClientMetadata;


/**
 * Tests the generic context.
 */
public class ContextTest extends TestCase {


	public void testMethods() {

		Context<ClientMetadata> ctx = new Context<>();

		assertNull(ctx.get());

		ClientMetadata metadata = new ClientMetadata();

		ctx.set(metadata);

		assertEquals(metadata, ctx.get());
	}
}
