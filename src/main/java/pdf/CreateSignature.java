package pdf;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Formatter;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuild;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuildDataDict;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.keystore.loader.implementation.DriverKeyStoreLoader;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class CreateSignature implements SignatureInterface {

	Certificate certificate = null;

	boolean signPdf(File pdfFile, File signedPdfFile) {
		try (FileOutputStream fos = new FileOutputStream(signedPdfFile); PDDocument doc = PDDocument.load(pdfFile)) {
			PDSignature signature = new PDSignature();
			signature.setFilter(COSName.getPDFName("PBAD_PAdES"));
			signature.setSubFilter(COSName.getPDFName("PBAD.PAdES"));
			// signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			// signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setName("JOSE RENE NERY CAILLERET CAMPANARIO");
			signature.setSignDate(Calendar.getInstance());
			PDPropBuild propBuild = new PDPropBuild();
			signature.setPropBuild(propBuild);
			PDPropBuildDataDict filter = new PDPropBuildDataDict();
			filter.setName(PDSignature.FILTER_ADOBE_PPKLITE.getName());
			filter.setDate((new Date()).toLocaleString());
			filter.setOS("Linux");
			filter.setTrustedMode(true);
			propBuild.setPDPropBuildFilter(filter);
			PDPropBuildDataDict app = new PDPropBuildDataDict();
			propBuild.setPDPropBuildApp(app);
			doc.addSignature(signature, this);
			doc.saveIncremental(fos);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public byte[] signWithDemoiselle(InputStream contentToSign) {
		try {
			// KeyStoreLoader keyStoreLoader =
			// KeyStoreLoaderFactory.factoryKeyStoreLoader();
			// KeyStore keyStore = keyStoreLoader.getKeyStore();
			DriverKeyStoreLoader loader = new DriverKeyStoreLoader();
			CallbackHandler callback = new CallbackHandler() {
				public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
					for (Callback callback : callbacks)
						if (callback instanceof PasswordCallback)
							((PasswordCallback) callback).setPassword("XXXX".toCharArray());
				}
			}; 
			loader.setCallbackHandler(callback);
			KeyStore keyStore = loader.getKeyStore();
			String alias = "(1288991) JOSE RENE NERY CAILLERET CAMPANARIO";
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
			Certificate[] certificateChain = keyStore.getCertificateChain(alias);
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(certificateChain);
			signer.setPrivateKey(privateKey);
			signer.setSignaturePolicy(Policies.AD_RT_PADES_1_1);
			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			byte[] content = IOUtils.toByteArray(contentToSign);
			byte[] signature = signer.doDetachedSign(content);
			return signature;
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] signWithBC(InputStream is) {
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(new File("D:/dev/workspace/pdf-tests/src/main/resources/key.jks")), null);
			Certificate certificate = keyStore.getCertificate("test");
			PrivateKey privateKey = (PrivateKey) keyStore.getKey("test", "".toCharArray());
			List<Certificate> certList = new ArrayList<Certificate>();
			certList.add(certificate);
			Store certs = new JcaCertStore(certList);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
					.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
			ContentSigner signer = new JcaContentSignerBuilder("SHA512WithRSA").build(privateKey);
			gen.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer,
							new X509CertificateHolder(cert)));
			gen.addCertificates(certs);
			CMSProcessableByteArray cmsPba = new CMSProcessableByteArray(IOUtils.toByteArray(is));
			CMSSignedData signedData = gen.generate(cmsPba, false);
			return signedData.getEncoded();
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] sign(InputStream is) {
		return this.signWithDemoiselle(is);
		// return this.signWithBC(is);
	}

	public static void main(String[] args) throws IOException, GeneralSecurityException, SignatureException {
		System.setProperty("mscapi.disabled", "true");
		File inFile = new File("D:/dev/workspace/pdf-tests/src/main/resources/001.pdf");
		File outFile = new File("D:/dev/workspace/pdf-tests/src/main/resources/001-assinado.pdf");
		new CreateSignature().signPdf(inFile, outFile);
		System.out.println("Fim.");
	}


}