package pdf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

import com.sun.security.auth.callback.DialogCallbackHandler;

public class AssinaturaExterna {

    public static void main(String[] args) throws Throwable {
        String fileName = "/home/09275643784/teste-original.pdf";
        byte[] hash = AssinaturaExterna.gerarHash(fileName);
        byte[] assinatura = AssinaturaExterna.assinarComHash(hash);
        AssinaturaExterna.acoplarAssinatura(assinatura, fileName);
    }

    public static void acoplarAssinatura(byte[] assinatura, String path) throws Throwable {
        String pathOutput = path.replaceAll(".pdf", "-assinatura.pdf");
        File file = new File(path);
        File fileOut = new File(pathOutput);
        PDDocument doc = PDDocument.load(file);
        doc.addSignature(AssinaturaExterna.criarPDFSig());
        doc.setDocumentId(1l);
        ExternalSigningSupport externalSigningSupport = doc.saveIncrementalForExternalSigning(new FileOutputStream(fileOut));
        externalSigningSupport.setSignature(assinatura);
        doc.close();
    }

    public static byte[] gerarHash(String path) throws Throwable {
        File file = new File(path);
        PDDocument doc = PDDocument.load(file);
        doc.addSignature(AssinaturaExterna.criarPDFSig());
        doc.setDocumentId(1l);
        ExternalSigningSupport externalSigningSupport = doc.saveIncrementalForExternalSigning(null);
        InputStream in = externalSigningSupport.getContent();
		byte[] content = null;
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();){
			IOUtils.copy(in, out);
			content = out.toByteArray();
		}
        in.close();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(content);
		byte[] hash = md.digest();
        return hash;        
    }

    public static PDSignature criarPDFSig() {
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        return signature;
    }

    public static byte[] assinarComHash(byte[] hash) throws Throwable {
        KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
        loader.setCallbackHandler(new DialogCallbackHandler());
        String signerAlgorithm = SignerAlgorithmEnum.SHA256withRSA.getAlgorithm();
        KeyStore keyStore = loader.getKeyStore();
        String alias = keyStore.aliases().nextElement();
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, null);
        Certificate[] chain = CAManager.getInstance().getCertificateChainArray(certificate);
        PKCS7Signer signer = PKCS7Factory.getInstance().factory();
        signer.setAlgorithm(signerAlgorithm);
        signer.setSignaturePolicy(Policies.AD_RB_CADES_2_2);
        signer.setPrivateKey(privateKey);
        signer.setCertificates(chain);
        signer.setProvider(keyStore.getProvider());
        byte[] assinatura = signer.doHashSign(hash);
        return assinatura;
    }

}