package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;

import net.jcip.annotations.ThreadSafe;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;


/**
 * SAML 2.0 assertion factory. Creates minimal assertions signed with
 * RSA-SHA256 (mandatory to implement XML signature).
 */
@ThreadSafe
public class SAML2AssertionFactory {


	/**
	 * The XML element builder.
	 */
	private final XMLObjectBuilderFactory builderFactory;


	/**
	 * The SAML 2.0 assertion issuer.
	 */
	private final String issuer;


	/**
	 * The subject name ID format.
	 */
	private final String subjectFormat;


	/**
	 * The SAML 2.0 assertion lifetime, in seconds.
	 */
	private final int lifetime;


	/**
	 * The RSA credential for signing the SAML 2.0 assertion.
	 */
	private final Credential signingCredential;


	/**
	 * Creates a new SAML 2.0 assertion factory.
	 *
	 * @param issuer            The SAML 2.0 assertion issuer. Must not be
	 *                          {@code null}.
	 * @param subjectFormat     The subject name ID format. See
	 *                          {@link org.opensaml.saml2.core.NameIDType}.
	 *                          Must not be {@code null}.
	 * @param lifetime          The SAML 2.0 assertion lifetime, in
	 *                          seconds.
	 * @param signingCredential The RSA credential for signing the
	 *                          assertions. Must not be {@code null}.
	 *
	 * @throws ConfigurationException If bootstrapping of the OpenSAML
	 *                                library failed.
	 */
	public SAML2AssertionFactory(final String issuer, final String subjectFormat, final int lifetime, final Credential signingCredential)
		throws ConfigurationException {

		if (issuer == null) {
			throw new IllegalArgumentException("The issuer must not be null");
		}
		this.issuer = issuer;

		if (subjectFormat == null) {
			throw new IllegalArgumentException("The subject name ID format must not be null");
		}
		this.subjectFormat = subjectFormat;

		this.lifetime = lifetime;

		if (! (signingCredential.getPrivateKey() instanceof RSAPrivateKey)) {
			throw new IllegalArgumentException("The signing credential must contain an RSA private key");
		}
		this.signingCredential = signingCredential;

		DefaultBootstrap.bootstrap();
		builderFactory = Configuration.getBuilderFactory();
	}


	/**
	 * Returns the SAML 2.0 assertion issuer.
	 *
	 * @return The issuer.
	 */
	public String getIssuer() {

		return issuer;
	}


	/**
	 * Returns the subject name ID format. See
	 * {@link org.opensaml.saml2.core.NameIDType}.
	 *
	 * @return The subject format.
	 */
	public String getSubjectFormat() {

		return subjectFormat;
	}


	/**
	 * Returns the lifetime of the created SAML 2.0 assertions.
	 *
	 * @return The assertion lifetime, in seconds.
	 */
	public int getAssertionLifetime() {

		return lifetime;
	}


	/**
	 * Returns the RSA signing credential.
	 *
	 * @return The signing credential.
	 */
	public Credential getSigningCredential() {

		return signingCredential;
	}


	/**
	 * Creates a new SAML 2.0 assertion for the specified audience and
	 * subject.
	 *
	 * @param audience The assertion audience. Must not be {@code null}.
	 * @param subject  The assertion subject. Must not be {@code null}.
	 *
	 * @return The assertion, signed with RSA-SHA256.
	 */
	public Assertion createAssertion(final URI audience,
					 final String subject)
		throws SignatureException, MarshallingException {

		// Top level assertion element
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		final DateTime now = new DateTime();

		Assertion a = assertionBuilder.buildObject();
		a.setID(UUID.randomUUID().toString());
		a.setIssueInstant(now);

		// Issuer
		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer iss = issuerBuilder.buildObject();
		iss.setValue(issuer);
		a.setIssuer(iss);

		// Conditions
		SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		Conditions conditions = conditionsBuilder.buildObject();

		// Audience restriction
		SAMLObjectBuilder<AudienceRestriction> audRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		AudienceRestriction audRestriction = audRestrictionBuilder.buildObject();

		// ... with single audience - the authz server
		SAMLObjectBuilder<Audience> audBuilder = (SAMLObjectBuilder<Audience>) builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
		Audience aud = audBuilder.buildObject();
		aud.setAudienceURI(audience.toString());
		audRestriction.getAudiences().add(aud);

		conditions.getAudienceRestrictions().add(audRestriction);

		a.setConditions(conditions);


		// Subject elements
		SAMLObjectBuilder<Subject> subBuilder = (SAMLObjectBuilder<Subject>) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject sub = subBuilder.buildObject();

		SAMLObjectBuilder<NameID> subIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = subIDBuilder.buildObject();
		nameID.setFormat(subjectFormat);
		nameID.setValue(subject);
		sub.setNameID(nameID);

		SAMLObjectBuilder<SubjectConfirmation> subCmBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subCm = subCmBuilder.buildObject();
		subCm.setMethod(SubjectConfirmation.METHOD_BEARER);

		SAMLObjectBuilder<SubjectConfirmationData> subCmDataBuilder= (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData subCmData = subCmDataBuilder.buildObject();
		subCmData.setNotOnOrAfter(now.plusSeconds(lifetime));
		subCmData.setRecipient(audience.toString());

		subCm.setSubjectConfirmationData(subCmData);

		sub.getSubjectConfirmations().add(subCm);

		a.setSubject(sub);


		// Signature
		Signature signature = (Signature) Configuration.getBuilderFactory()
			.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
			.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		a.setSignature(signature);

		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		marshallerFactory.getMarshaller(a).marshall(a);
		Signer.signObject(signature);

		return a;
	}


	/**
	 * Creates a new SAML 2.0 assertion XML element for the specified
	 * audience and subject.
	 *
	 * @param audience The assertion audience. Must not be {@code null}.
	 * @param subject  The assertion subject. Must not be {@code null}.
	 *
	 * @return The assertion, signed with RSA-SHA256.
	 */
	public Element createAssertionElement(final URI audience, final String subject)
		throws SignatureException, MarshallingException {

		Assertion a = createAssertion(audience, subject);

		AssertionMarshaller assertionMarshaller = new AssertionMarshaller();
		return assertionMarshaller.marshall(a);
	}


	/**
	 * Creates a new SAML 2.0 assertion XML document for the specified
	 * audience and subject.
	 *
	 * @param audience The assertion audience. Must not be {@code null}.
	 * @param subject  The assertion subject. Must not be {@code null}.
	 *
	 * @return The assertion, signed with RSA-SHA256.
	 */
	public String createAssertionString(final URI audience, final String subject)
		throws SignatureException, MarshallingException {

		Element a = createAssertionElement(audience, subject);
		String xml = XMLHelper.nodeToString(a);
		// Strip header
		final String header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		return xml.substring(header.length());
	}
}
