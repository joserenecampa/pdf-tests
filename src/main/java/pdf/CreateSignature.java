package pdf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuild;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuildDataDict;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
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

public class CreateSignature implements SignatureInterface {
	
	boolean signPdf(File pdfFile, File signedPdfFile) {
		try (
			FileOutputStream fos = new FileOutputStream(signedPdfFile);
			PDDocument doc = PDDocument.load(pdfFile)) {
			float version = doc.getVersion();
			System.out.println(version);
			PDSignature signature = new PDSignature();
//			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
//			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setFilter(COSName.getPDFName("PBAD_PAdES"));
			signature.setSubFilter(COSName.getPDFName("PBAD.PAdES"));
			signature.setName("José René Nery Cailleret Campanario");
			signature.setLocation("LOCATION");
			signature.setReason("REASON");
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

	@Override
	public byte[] sign(InputStream is) {
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(new File("/home/rene/dev/pdf-tests/src/main/resources/key.jks")), null);
			Certificate certificate = keyStore.getCertificate("test");
			PrivateKey privateKey = (PrivateKey)keyStore.getKey("test", "".toCharArray());
			List<Certificate> certList = new ArrayList<Certificate>();
			certList.add(certificate);
			Store certs = new JcaCertStore(certList);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
			ContentSigner signer = new JcaContentSignerBuilder("SHA512WithRSA").build(privateKey);
			gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, new X509CertificateHolder(cert)));
			gen.addCertificates(certs);
			CMSProcessableByteArray cmsPba = new CMSProcessableByteArray(IOUtils.toByteArray(is));
			CMSSignedData signedData = gen.generate(cmsPba, false);
			return signedData.getEncoded();
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
}

	public static void main(String[] args) throws IOException, GeneralSecurityException, SignatureException {
		File inFile = new File("/home/rene/Área de Trabalho/ass/001.pdf");
		File outFile = new File("/home/rene/Área de Trabalho/ass/001-assinado.pdf");
		new CreateSignature().signPdf(inFile, outFile);
		System.out.println("Fim.");
	}
}