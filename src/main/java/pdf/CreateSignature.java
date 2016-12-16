package pdf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import com.sun.security.auth.callback.DialogCallbackHandler;

import br.gov.frameworkdemoiselle.certificate.ca.manager.CAManager;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoader;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.configuration.Configuration;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.factory.KeyStoreLoaderFactory;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS7Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.SignaturePolicy;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.policies.ADRBCMS_2_2;

public class CreateSignature implements SignatureInterface {
	
	private static PrivateKey privateKey;
	private static Certificate certificate;

	boolean signPdf(File pdfFile, File signedPdfFile) {
		try (FileInputStream fis1 = new FileInputStream(pdfFile);
				FileInputStream fis = new FileInputStream(pdfFile);
				FileOutputStream fos = new FileOutputStream(signedPdfFile);
				PDDocument doc = PDDocument.load(pdfFile)) {
			int readCount;
			byte[] buffer = new byte[8 * 1024];
			while ((readCount = fis1.read(buffer)) != -1) {
				fos.write(buffer, 0, readCount);
			}
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setName("José René Nery Cailleret Campanario");
			signature.setLocation("LOCATION");
			signature.setReason("REASON");
			signature.setSignDate(Calendar.getInstance());
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
			try {
				
				String toSigner = "HELLO WORLD!";
				
				String algoritmo = "SHA256withRSA";
				
				CallbackHandler callback = null;
				File file = new File("/tmp/ptk");
				if (file.exists()) {
					final byte[] content = new byte[(int)file.length()];
					FileInputStream fis = new FileInputStream(file);
					fis.read(content);
					fis.close();
					callback = new CallbackHandler() {
						public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
							for (Callback callback : callbacks) {
								if (callback instanceof PasswordCallback) {
									System.out.print("Setando o PIN: ");
									((PasswordCallback)callback).setPassword(new String(content).trim().replaceAll("\n", "").toCharArray());
									System.out.println("OK");
								}
							}
						}
					};
				} else {
					callback = new DialogCallbackHandler();
				}
				
				String signerAlgorithm = SignerAlgorithmEnum.SHA512withRSA.getAlgorithm();
				
				if (algoritmo != null && algoritmo.trim().startsWith("256"))
					signerAlgorithm = SignerAlgorithmEnum.SHA256withRSA.getAlgorithm();
				
				SignaturePolicy signaturePolicy = new ADRBCMS_2_2();
				
				System.out.println("Iniciando o teste de assinatura");
				System.out.println("JVM: " + System.getProperty("java.vendor") + " - " + System.getProperty("java.version"));
				System.out.print("Fabricando KeyStoreLoader: ");
				KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
				System.out.println("OK");
				System.out.print("Setando o callback para o PIN: ");
				loader.setCallbackHandler(callback);
				System.out.println("OK");
				System.out.println("Carregando KeyStore");
				KeyStore keyStore = loader.getKeyStore();
				String providerName = keyStore.getProvider().toString();
				String tokenConfigName = providerName.split(" ")[0].split("-")[1];
				String pathDriver = Configuration.getInstance().getDrivers().get(tokenConfigName);
				System.out.println("KeyStore carregado. Provider [" + providerName + "] [" + pathDriver + "]");
				System.out.print("Pegando o primeiro alias: ");
				String alias = keyStore.aliases().nextElement();
				System.out.println(alias);
				System.out.print("Pegando o certificado do alias acima: ");
				X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
				System.out.println("OK");
				System.out.print("Pegando a referencia a chave privada: ");
				PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, null);
				System.out.println("OK");
				System.out.print("Buscando a cadeia de autoridades do certificado: ");
				Certificate[] chain = CAManager.getInstance().getCertificateChainArray(certificate);
				System.out.println("OK");
				System.out.println("Instanciando os objetos do Demoiselle Certificate");
				
				PKCS7Signer signer = PKCS7Factory.getInstance().factory();
				System.out.println("Configurando assinatura com conteúdo não atachado");
				signer.setAttached(false);
				System.out.println("Configurando algoritmo " + signerAlgorithm);
				signer.setAlgorithm(signerAlgorithm);
				System.out.println("Configurando Política de Assinatua: " + signaturePolicy.getClass().getSimpleName());
				signer.setSignaturePolicy(signaturePolicy);
				System.out.println("Informando para o componente a chave privada");
				signer.setPrivateKey(privateKey);
				System.out.println("Informando para o componente a cadeia de certificado");
				signer.setCertificates(chain);
				byte[] content = toSigner.getBytes();
				System.out.print("Montando bytes para assinatura: " + toSigner + ". ");
				System.out.println("OK");
				System.out.print("Tudo pronto. Assinando ... ");
				signer.setProvider(keyStore.getProvider());
				byte[] assinatura = signer.signer(content);
				System.out.println("OK");
				System.out.println("Assinatura: Tamanho: " + assinatura.length + " bytes");
				System.out.print("Validando a assinatura: ");
				signer.check(content, assinatura);
				System.out.println("OK");
				return assinatura;
			} catch (Throwable error) {
				System.out.println("Algo falhou: " + error.getMessage() + (error.getCause()!=null?" Causa: "+error.getCause().getMessage():". sem causa."));
				error.printStackTrace();
				return null;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void main(String[] args) throws IOException, GeneralSecurityException, SignatureException {
		File inFile = new File("/home/09275643784/Área de Trabalho/folhaponto.pdf");
		File outFile = new File("/home/09275643784/Área de Trabalho/folhaponto-assinado.pdf");
		new CreateSignature().signPdf(inFile, outFile);
	}
}