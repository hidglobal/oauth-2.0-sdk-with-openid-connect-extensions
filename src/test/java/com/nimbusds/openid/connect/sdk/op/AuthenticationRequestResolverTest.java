package com.nimbusds.openid.connect.sdk.op;


import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.Resource;
import com.nimbusds.oauth2.sdk.http.ResourceRetriever;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import junit.framework.TestCase;


/**
 * Tests the OpenID authentication request resolver.
 */
public class AuthenticationRequestResolverTest extends TestCase {
	

	public void testRequestObjectsUnsupported()
		throws ResolveException, JOSEException {

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver();
		assertNull(resolver.getJWTRetriever());
		assertNull(resolver.getJWTProcessor());

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid email"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.build();

		// Pass through
		assertEquals(request, resolver.resolve(request, null));

		// Reject request_object
		JWT requestObject = new PlainJWT(new JWTClaimsSet.Builder()
			.claim("scope", "openid email profile")
			.build());

		request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.requestObject(requestObject)
			.build();

		try {
			resolver.resolve(request, null);
		} catch (ResolveException e) {
			assertEquals(OIDCError.REQUEST_NOT_SUPPORTED.getCode(), e.getErrorObject().getCode());
			assertEquals(OIDCError.REQUEST_NOT_SUPPORTED.getDescription(), e.getErrorObject().getDescription());
			assertEquals(request.getClientID(), e.getClientID());
			assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
			assertNull(e.getState());
			assertNull(e.getResponseMode());
		}


		// Reject request_uri
		request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.requestURI(URI.create("https://example.com/request.jwt"))
			.build();

		try {
			resolver.resolve(request, null);
		} catch (ResolveException e) {
			assertEquals(OIDCError.REQUEST_URI_NOT_SUPPORTED.getCode(), e.getErrorObject().getCode());
			assertEquals(OIDCError.REQUEST_URI_NOT_SUPPORTED.getDescription(), e.getErrorObject().getDescription());
			assertEquals(request.getClientID(), e.getClientID());
			assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
			assertNull(e.getState());
			assertNull(e.getResponseMode());
		}
	}


	public void testRequestObjectsOnly_plainJWT()
		throws ResolveException, JOSEException {

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor() {
			@Override
			public JWTClaimsSet process(final PlainJWT plainJWT, final SecurityContext context)
				throws BadJOSEException, JOSEException {
				try {
					return plainJWT.getJWTClaimsSet();
				} catch (ParseException e) {
					throw new BadJOSEException(e.getMessage(), e);
				}
			}
		};

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		JWT requestObject = new PlainJWT(new JWTClaimsSet.Builder()
			.claim("scope", "openid email")
			.claim("redirect_uri", "https://example.com/cb")
			.claim("claims", claimsRequest.toJSONObject())
			.build());

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			null)
			.state(new State("xyz"))
			.requestObject(requestObject)
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor);

		request = resolver.resolve(request, null);

		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(Scope.parse("openid email"), request.getScope());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertEquals(new State("xyz"), request.getState());
		claimsRequest = request.getClaims();
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("name"));
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("given_name"));
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("family_name"));
		assertEquals(3, claimsRequest.getIDTokenClaimNames(false).size());
		assertTrue(claimsRequest.getUserInfoClaimNames(false).isEmpty());
		assertEquals(6, request.toParameters().size());
	}


	public void testRequestObjectsOnly_plainJWT_missingRedirectURI()
		throws ResolveException, JOSEException {

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor() {
			@Override
			public JWTClaimsSet process(final PlainJWT plainJWT, final SecurityContext context)
				throws BadJOSEException, JOSEException {
				try {
					return plainJWT.getJWTClaimsSet();
				} catch (ParseException e) {
					throw new BadJOSEException(e.getMessage(), e);
				}
			}
		};

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		JWT requestObject = new PlainJWT(new JWTClaimsSet.Builder()
			.claim("scope", "openid email")
			.claim("claims", claimsRequest.toJSONObject())
			.build());

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			null)
			.state(new State("xyz"))
			.requestObject(requestObject)
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor);

		try {
			resolver.resolve(request, null);
		} catch (ResolveException e) {
			assertEquals("Couldn't create final OpenID authentication request: Missing \"redirect_uri\" parameter", e.getMessage());
			assertEquals(OIDCError.INVALID_REQUEST_OBJECT.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request object parameter(s): Missing \"redirect_uri\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getRedirectionURI());
			assertEquals(request.getState(), e.getState());
		}
	}


	public void testRequestObjectsOnly_plainJWT_bypassRegularAuthRequest()
		throws ResolveException, JOSEException {

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor() {
			@Override
			public JWTClaimsSet process(final PlainJWT plainJWT, final SecurityContext context)
				throws BadJOSEException, JOSEException {
				try {
					return plainJWT.getJWTClaimsSet();
				} catch (ParseException e) {
					throw new BadJOSEException(e.getMessage(), e);
				}
			}
		};

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("xyz"))
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor);

		assertEquals(request, resolver.resolve(request, null));
	}


	public void testRequestObjectsOnly_plainJWT_badClaimsSetJSON()
		throws ResolveException, JOSEException, ParseException {

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor() {
			@Override
			public JWTClaimsSet process(final PlainJWT plainJWT, final SecurityContext context)
				throws BadJOSEException, JOSEException {
				try {
					return plainJWT.getJWTClaimsSet();
				} catch (ParseException e) {
					throw new BadJOSEException(e.getMessage(), e);
				}
			}
		};

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		PlainObject plainObject = new PlainObject(new Payload("not-json-object"));
		JWT requestObject = JWTParser.parse(plainObject.serialize());

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			null)
			.state(new State("xyz"))
			.requestObject(requestObject)
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor);

		try {
			resolver.resolve(request, null);
		} catch (ResolveException e) {
			assertEquals("Invalid request object: Payload of unsecured JOSE object is not a valid JSON object", e.getMessage());
			assertEquals(OIDCError.INVALID_REQUEST_OBJECT.getCode(), e.getErrorObject().getCode());
			assertEquals("Bad JWT / signature / HMAC / encryption", e.getErrorObject().getDescription());
			assertNull(e.getRedirectionURI());
			assertEquals(request.getState(), e.getState());
		}
	}


	public void testRequestURI_hmacJWT()
		throws ResolveException, JOSEException {

		final Secret clientSecret = new Secret();

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(new JWSKeySelector() {
			@Override
			public List<SecretKey> selectJWSKeys(JWSHeader header, SecurityContext context) {
				if (! JWSAlgorithm.HS256.equals(header.getAlgorithm())) {
					return null; // unsupported alg
				}
				SecretKey hmacKey = new SecretKeySpec(clientSecret.getValueBytes(), "HmacSha256");
				return Collections.singletonList(hmacKey);
			}
		});

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		final SignedJWT requestObject = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
			.claim("scope", "openid email")
			.claim("redirect_uri", "https://example.com/cb")
			.claim("claims", claimsRequest.toJSONObject())
			.build());
		requestObject.sign(new MACSigner(clientSecret.getValueBytes()));

		ResourceRetriever jwtRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {
				return new Resource(requestObject.serialize(), CommonContentTypes.APPLICATION_JWT);
			}
		};

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			null)
			.state(new State("xyz"))
			.requestURI(URI.create("https://example.com/request.jwt"))
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor, jwtRetriever);

		request = resolver.resolve(request, null);

		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(Scope.parse("openid email"), request.getScope());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertEquals(new State("xyz"), request.getState());
		claimsRequest = request.getClaims();
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("name"));
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("given_name"));
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("family_name"));
		assertEquals(3, claimsRequest.getIDTokenClaimNames(false).size());
		assertTrue(claimsRequest.getUserInfoClaimNames(false).isEmpty());
		assertEquals(6, request.toParameters().size());
	}


	public void testRequestURI_hmacJWT_badHMAC()
		throws ResolveException, JOSEException {

		final Secret clientSecret = new Secret();

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(new JWSKeySelector() {
			@Override
			public List<SecretKey> selectJWSKeys(JWSHeader header, SecurityContext context) {
				if (! JWSAlgorithm.HS256.equals(header.getAlgorithm())) {
					return null; // unsupported alg
				}
				// Generate random secret to cause HMAC mismatch
				SecretKey hmacKey = new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256");
				return Collections.singletonList(hmacKey);
			}
		});

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		final SignedJWT requestObject = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
			.claim("scope", "openid email")
			.claim("redirect_uri", "https://example.com/cb")
			.claim("claims", claimsRequest.toJSONObject())
			.build());
		requestObject.sign(new MACSigner(clientSecret.getValueBytes()));

		ResourceRetriever jwtRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {
				return new Resource(requestObject.serialize(), CommonContentTypes.APPLICATION_JWT);
			}
		};

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			null)
			.state(new State("xyz"))
			.requestURI(URI.create("https://example.com/request.jwt"))
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor, jwtRetriever);

		try {
			resolver.resolve(request, null);
		} catch (ResolveException e) {
			assertEquals("Invalid request object: Signed JWT rejected: Invalid signature", e.getMessage());
			assertEquals(OIDCError.INVALID_REQUEST_URI.getCode(), e.getErrorObject().getCode());
			assertEquals("Bad JWT / signature / HMAC / encryption", e.getErrorObject().getDescription());
			assertNull(e.getRedirectionURI());
			assertEquals(request.getState(), e.getState());
		}
	}


	public void testRequestURI_hmacJWT_badURL()
		throws ResolveException, JOSEException {

		final Secret clientSecret = new Secret();

		DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(new JWSKeySelector() {
			@Override
			public List<SecretKey> selectJWSKeys(JWSHeader header, SecurityContext context) {
				if (! JWSAlgorithm.HS256.equals(header.getAlgorithm())) {
					return null; // unsupported alg
				}
				// Generate random secret to cause HMAC mismatch
				SecretKey hmacKey = new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256");
				return Collections.singletonList(hmacKey);
			}
		});

		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("name");
		claimsRequest.addIDTokenClaim("given_name");
		claimsRequest.addIDTokenClaim("family_name");

		final SignedJWT requestObject = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
			.claim("scope", "openid email")
			.claim("redirect_uri", "https://example.com/cb")
			.claim("claims", claimsRequest.toJSONObject())
			.build());
		requestObject.sign(new MACSigner(clientSecret.getValueBytes()));

		ResourceRetriever jwtRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {
				throw new IOException("Connect timeout");
			}
		};

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			Scope.parse("openid"),
			new ClientID("123"),
			null)
			.state(new State("xyz"))
			.requestURI(URI.create("https://example.com/request.jwt"))
			.build();

		AuthenticationRequestResolver resolver = new AuthenticationRequestResolver(jwtProcessor, jwtRetriever);

		try {
			resolver.resolve(request, null);
		} catch (ResolveException e) {
			assertEquals("Couldn't retrieve request_uri: Connect timeout", e.getMessage());
			assertEquals(OIDCError.INVALID_REQUEST_URI.getCode(), e.getErrorObject().getCode());
			assertEquals("Network error, check the request_uri", e.getErrorObject().getDescription());
			assertNull(e.getRedirectionURI());
			assertEquals(request.getState(), e.getState());
		}
	}
}
