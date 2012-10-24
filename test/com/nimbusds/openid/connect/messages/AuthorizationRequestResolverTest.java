// Resolve simple parameters
		try {
			// resolve response_type
			rts = req.getResolvedResponseTypeSet();
			assertNotNull(rts);
			assertTrue(rts.contains(ResponseType.CODE));
			assertTrue(rts.contains(ResponseType.ID_TOKEN));
			assertEquals(2, rts.size());
			
			// resolve client_id
			assertEquals("s6BhdRkqt3", req.getResolvedClientID().getClaimValue());
			
			// resolve redirect_uri
			assertEquals("https://client.example.com/cb", req.getResolvedRedirectURI().toString());
			
			// resolve scope
			scope = req.getResolvedScope();
			assertNotNull(scope);
			assertTrue(scope.contains(StdScopeToken.OPENID));
			assertTrue(scope.contains(StdScopeToken.PROFILE));
			assertEquals(2, scope.size());
			
			// resolve state
			assertEquals(new Nonce("n-0S6_WzA2Mj"), req.getResolvedNonce());
		
			// resolve nonce
			assertEquals(new State("af0ifjsldkj"), req.getResolvedState());
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		
		// Resolve claims
		ResolvedIDTokenClaimsRequest idTokenClaimsRequest = null;
		ResolvedUserInfoClaimsRequest userInfoClaimsRequest = null;
		
		try {
			idTokenClaimsRequest = req.getResolvedIDTokenClaimsRequest();
			userInfoClaimsRequest = req.getResolvedUserInfoClaimsRequest();
			
			assertEquals(86400, idTokenClaimsRequest.getMaxAge());
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		// ID Token claims
		
		Set<String> allClaims = idTokenClaimsRequest.getClaims();
		
		assertTrue(allClaims.contains("iss"));
		assertTrue(allClaims.contains("user_id"));
		assertTrue(allClaims.contains("aud"));
		assertTrue(allClaims.contains("exp"));
		assertTrue(allClaims.contains("iat"));
		assertTrue(allClaims.contains("nonce"));
		assertTrue(allClaims.contains("acr"));
		
		Set<String> requiredClaims = idTokenClaimsRequest.getRequiredClaims();
		
		assertTrue(requiredClaims.contains("iss"));
		assertTrue(requiredClaims.contains("user_id"));
		assertTrue(requiredClaims.contains("aud"));
		assertTrue(requiredClaims.contains("exp"));
		assertTrue(requiredClaims.contains("iat"));
		assertTrue(requiredClaims.contains("nonce"));
		
		try {
			assertNull(idTokenClaimsRequest.getUserID());
			assertEquals(86400, idTokenClaimsRequest.getMaxAge());
			String[] acr = idTokenClaimsRequest.getAuthenticationContextClassReference();
			
			assertEquals(1, acr.length);
			assertEquals("2", acr[0]);
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		Set<String> optionalClaims = idTokenClaimsRequest.getOptionalClaims();
		
		assertEquals(0, optionalClaims.size());
		
		
		// UserInfo claims
		
		allClaims = userInfoClaimsRequest.getClaims();
		
		assertTrue(allClaims.contains("user_id"));
		assertTrue(allClaims.contains("name"));
		assertTrue(allClaims.contains("family_name"));
		assertTrue(allClaims.contains("given_name"));
		assertTrue(allClaims.contains("middle_name"));
		assertTrue(allClaims.contains("nickname"));
		assertTrue(allClaims.contains("profile"));
		assertTrue(allClaims.contains("picture"));
		assertTrue(allClaims.contains("website"));
		assertTrue(allClaims.contains("gender"));
		assertTrue(allClaims.contains("birthday"));
		assertTrue(allClaims.contains("zoneinfo"));
		assertTrue(allClaims.contains("locale"));
		assertTrue(allClaims.contains("updated_time"));
		
		assertTrue(allClaims.contains("email"));
		assertTrue(allClaims.contains("verified"));
		
		assertEquals(16, allClaims.size());
		
		requiredClaims = userInfoClaimsRequest.getRequiredClaims();
		
		assertTrue(requiredClaims.contains("user_id"));
		assertTrue(requiredClaims.contains("name"));
		assertTrue(requiredClaims.contains("email"));
		assertTrue(requiredClaims.contains("verified"));
		
		assertEquals(4, requiredClaims.size());
		
		optionalClaims = userInfoClaimsRequest.getOptionalClaims();
		
		assertTrue(optionalClaims.contains("family_name"));
		assertTrue(optionalClaims.contains("given_name"));
		assertTrue(optionalClaims.contains("middle_name"));
		assertTrue(optionalClaims.contains("nickname"));
		assertTrue(optionalClaims.contains("profile"));
		assertTrue(optionalClaims.contains("picture"));
		assertTrue(optionalClaims.contains("website"));
		assertTrue(optionalClaims.contains("gender"));
		assertTrue(optionalClaims.contains("birthday"));
		assertTrue(optionalClaims.contains("zoneinfo"));
		assertTrue(optionalClaims.contains("locale"));
		assertTrue(optionalClaims.contains("updated_time"));
		
		assertEquals(12, optionalClaims.size());
