package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import net.jcip.annotations.ThreadSafe;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


/**
 * SAML 2.0 assertion validator. Supports RSA signatures and HMAC. Provides
 * static methods for each validation step for putting together tailored
 * assertion validation strategies.
 */
@ThreadSafe
public class SAML2AssertionValidator {


	/**
	 * The SAML 2.0 assertion details verifier.
	 */
	private final SAML2AssertionDetailsVerifier detailsVerifier;


	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a new SAML 2.0 assertion validator.
	 *
	 * @param detailsVerifier The SAML 2.0 assertion details verifier. Must
	 *                        not be {@code null}.
	 */
	public SAML2AssertionValidator(final SAML2AssertionDetailsVerifier detailsVerifier) {
		if (detailsVerifier == null) {
			throw new IllegalArgumentException("The SAML 2.0 assertion details verifier must not be null");
		}
		this.detailsVerifier = detailsVerifier;
	}


	/**
	 * Gets the SAML 2.0 assertion details verifier.
	 *
	 * @return The SAML 2.0 assertion details verifier.
	 */
	public SAML2AssertionDetailsVerifier getDetailsVerifier() {
		return detailsVerifier;
	}


	/**
	 * Parses a SAML 2.0 assertion from the specified XML string.
	 *
	 * @param xml The XML string. Must not be {@code null}.
	 *
	 * @return The SAML 2.0 assertion.
	 *
	 * @throws ParseException If parsing of the assertion failed.
	 */
	public static Assertion parse(final String xml)
		throws ParseException {

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);

		XMLObject xmlObject;

		try {
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

			Document document = docBuilder.parse(new InputSource(new ByteArrayInputStream(xml.getBytes("utf-8"))));
			Element element = document.getDocumentElement();

			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
			xmlObject = unmarshaller.unmarshall(element);

		} catch (ParserConfigurationException | IOException | SAXException | UnmarshallingException e) {
			throw new ParseException("SAML 2.0 assertion parsing failed: " + e.getMessage(), e);
		}

		if (! (xmlObject instanceof Assertion)) {
			throw new ParseException("Top-level XML element not a SAML 2.0 assertion");
		}

		return (Assertion)xmlObject;
	}


	/**
	 * Verifies the specified XML signature (HMAC, RSA or EC) with the
	 * provided key.
	 *
	 * @param signature The XML signature. Must not be {@code null}.
	 * @param key       The key to verify the signature. Should be an
	 *                  {@link SecretKey} instance for HMAC,
	 *                  {@link RSAPublicKey} for RSA signatures or
	 *                  {@link ECPublicKey} for EC signatures. Must not be
	 *                  {@code null}.
	 *
	 * @throws BadSAML2AssertionException If the key type doesn't match the
	 *                                    signature, or the signature is
	 *                                    invalid.
	 */
	public static void verifySignature(final Signature signature, final Key key)
		throws BadSAML2AssertionException {

		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(signature);
		} catch (ValidationException e) {
			throw new BadSAML2AssertionException("Invalid SAML 2.0 signature format: " + e.getMessage(), e);
		}

		BasicCredential credential = new BasicCredential();
		if (key instanceof SecretKey) {
			credential.setSecretKey((SecretKey)key);
		} else if (key instanceof PublicKey) {
			credential.setPublicKey((PublicKey)key);
			credential.setUsageType(UsageType.SIGNING);
		} else {
			throw new BadSAML2AssertionException("Unsupported key type: " + key.getAlgorithm());
		}

		SignatureValidator signatureValidator = new SignatureValidator(credential);
		try {
			signatureValidator.validate(signature);
		} catch (ValidationException e) {
			throw new BadSAML2AssertionException("Bad SAML 2.0 signature: " + e.getMessage(), e);
		}
	}


	/**
	 * Validates the specified SAML 2.0 assertion.
	 *
	 * @param assertion The SAML 2.0 assertion XML. Must not be
	 *                  {@code null}.
	 * @param key       The key to verify the signature. Should be an
	 *                  {@link SecretKey} instance for HMAC,
	 *                  {@link RSAPublicKey} for RSA signatures or
	 *                  {@link ECPublicKey} for EC signatures. Must not be
	 *                  {@code null}.
	 *
	 * @return The validated SAML 2.0 assertion.
	 *
	 * @throws BadSAML2AssertionException If the assertion is invalid.
	 */
	public Assertion validate(final Assertion assertion,
				  final Issuer expectedIssuer,
				  final Key key)
		throws BadSAML2AssertionException {

		final SAML2AssertionDetails assertionDetails;

		try {
			assertionDetails = SAML2AssertionDetails.parse(assertion);
		} catch (ParseException e) {
			throw new BadSAML2AssertionException("Invalid SAML 2.0 assertion: " + e.getMessage(), e);
		}

		// Check the audience and time window details
		detailsVerifier.verify(assertionDetails);

		// Check the issuer
		if (! expectedIssuer.equals(assertionDetails.getIssuer())) {
			throw new BadSAML2AssertionException("Unexpected issuer: " + assertionDetails.getIssuer());
		}

		// Verify the signature
		verifySignature(assertion.getSignature(), key);

		return assertion; // OK
	}


	/**
	 * Validates the specified SAML 2.0 assertion.
	 *
	 * @param xml The SAML 2.0 assertion XML. Must not be {@code null}.
	 * @param key The key to verify the signature. Should be an
	 *            {@link SecretKey} instance for HMAC, {@link RSAPublicKey}
	 *            for RSA signatures or {@link ECPublicKey} for EC
	 *            signatures. Must not be {@code null}.
	 *
	 * @return The validated SAML 2.0 assertion.
	 *
	 * @throws BadSAML2AssertionException If the assertion is invalid.
	 */
	public Assertion validate(final String xml,
				  final Issuer expectedIssuer,
				  final Key key)
		throws BadSAML2AssertionException {

		// Parse string to XML, then to SAML 2.0 assertion object
		final Assertion assertion;

		try {
			assertion = parse(xml);
		} catch (ParseException e) {
			throw new BadSAML2AssertionException("Invalid SAML 2.0 assertion: " + e.getMessage(), e);
		}

		return validate(assertion, expectedIssuer, key);
	}
}
