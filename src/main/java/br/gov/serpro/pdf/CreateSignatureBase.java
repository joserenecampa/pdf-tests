/*
 * Copyright 2015 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package br.gov.serpro.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import br.gov.frameworkdemoiselle.certificate.ca.manager.CAManager;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS7Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.policies.ADRBCMS_2_2;

public abstract class CreateSignatureBase implements SignatureInterface {
	private PrivateKey privateKey;
	private Certificate certificate;
	private boolean externalSigning;

	/**
	 * Initialize the signature creator with a keystore (pkcs12) and pin that
	 * should be used for the signature.
	 *
	 * @param keystore
	 *            is a pkcs12 keystore.
	 * @param pin
	 *            is the pin for the keystore / private key
	 * @throws KeyStoreException
	 *             if the keystore has not been initialized (loaded)
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm for recovering the key cannot be found
	 * @throws UnrecoverableKeyException
	 *             if the given password is wrong
	 * @throws CertificateException
	 *             if the certificate is not valid as signing time
	 * @throws IOException
	 *             if no certificate could be found
	 */
	public CreateSignatureBase(KeyStore keystore, char[] pin) throws KeyStoreException, UnrecoverableKeyException,
			NoSuchAlgorithmException, IOException, CertificateException {
		// grabs the first alias from the keystore and get the private key. An
		// alternative method or constructor could be used for setting a
		// specific
		// alias that should be used.
		Enumeration<String> aliases = keystore.aliases();
		String alias;
		Certificate cert = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
			Certificate[] certChain = keystore.getCertificateChain(alias);
			if (certChain == null) {
				continue;
			}
			cert = certChain[0];
			setCertificate(cert);
			if (cert instanceof X509Certificate) {
				// avoid expired certificate
				((X509Certificate) cert).checkValidity();
			}
			break;
		}

		if (cert == null) {
			throw new IOException("Could not find certificate");
		}
	}

	public final void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public final void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}

	/**
	 * SignatureInterface implementation.
	 *
	 * This method will be called from inside of the pdfbox and create the PKCS
	 * #7 signature. The given InputStream contains the bytes that are given by
	 * the byte range.
	 *
	 * This method is for internal use only.
	 *
	 * Use your favorite cryptographic library to implement PKCS #7 signature
	 * creation.
	 */
	@Override
	public byte[] sign(InputStream contentToSign) throws IOException {
//		// TODO this method should be private
//		try {
//			List<Certificate> certList = new ArrayList<Certificate>();
//			certList.add(certificate);
//			Store certs = new JcaCertStore(certList);
//			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
//			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
//					.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
//			ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
//			gen.addSignerInfoGenerator(
//					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
//							.build(sha1Signer, new X509CertificateHolder(cert)));
//			gen.addCertificates(certs);
//			CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
//			CMSSignedData signedData = gen.generate(msg, false);
//			if (tsaClient != null) {
//				signedData = signTimeStamps(signedData);
//			}
//			return signedData.getEncoded();
//		} catch (GeneralSecurityException e) {
//			throw new IOException(e);
//		} catch (CMSException e) {
//			throw new IOException(e);
//		} catch (TSPException e) {
//			throw new IOException(e);
//		} catch (OperatorCreationException e) {
//			throw new IOException(e);
//		}
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int nRead;
		byte[] data = new byte[16384];
		while ((nRead = contentToSign.read(data, 0, data.length)) != -1)
		  buffer.write(data, 0, nRead);
		buffer.flush();
		byte[] content = buffer.toByteArray();		
		try {
			Certificate[] chain = CAManager.getInstance().getCertificateChainArray((X509Certificate)certificate);
			PKCS7Signer signer = PKCS7Factory.getInstance().factory();
			signer.setAttached(false);
			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			signer.setSignaturePolicy(new ADRBCMS_2_2());
			signer.setPrivateKey(privateKey);
			signer.setCertificates(chain);
			byte[] assinatura = signer.signer(content);
			signer.check(content, assinatura);
			return assinatura;
		} catch (Throwable error) {
			error.printStackTrace();
			return null;
		}
	}

	/**
	 * Set if external signing scenario should be used. If {@code false},
	 * SignatureInterface would be used for signing.
	 * <p>
	 * Default: {@code false}
	 * </p>
	 * 
	 * @param externalSigning
	 *            {@code true} if external signing should be performed
	 */
	public void setExternalSigning(boolean externalSigning) {
		this.externalSigning = externalSigning;
	}

	public boolean isExternalSigning() {
		return externalSigning;
	}
}