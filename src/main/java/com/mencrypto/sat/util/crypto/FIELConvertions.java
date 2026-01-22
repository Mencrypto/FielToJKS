package com.mencrypto.sat.util.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Clase de utileria para tratar certificados  y llaves de la Firma Electronica FIEL
 * emitida por el Sistema de Administración Tributaría SAT
 * Permite convertir a almacenes de llave pfx o p12 y  Java Key Store JKS
 * Lo que puede ayudar en la automatización o uso en otros proyectos
 * 
 * @author Mencryto
 * @version 1.0
 */
public class FIELConvertions {
	
	/**
	 * Convierte una llave en formato pkcs8 con contraseña a PEM sin contraseña
	 * y la escribe en la misma ruta en que se encuentre el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param password Es la contraseña para la llave FIEL
	 * @return String con la ruta en la que se escribió el archivo .pem
	 */
	static String convertKeyDERToPEM(File keypkcs8, String password) {
		// Ruta donde se guardará el archivo PEM sin contraseña con extensión .pem
		String outputhPath = keypkcs8.getAbsolutePath().substring(0, keypkcs8.getAbsolutePath().lastIndexOf("."))+ ".pem";

		PrivateKey privatKey = loadPrivateKey(keypkcs8, password);
		// Cambiar de llave RSA a PEM sin contraseña
		PemObject pemObject = new PemObject("PRIVATE KEY", privatKey.getEncoded());
		File outputPemFile = new File(outputhPath);
		// Escribir PEM SIN contraseña
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(outputPemFile))) {
			pemWriter.writeObject(pemObject);
			System.out.println("Llave PEM generada correctamente en: " + outputhPath);
			return outputhPath;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Convierte un certificado con llave pública en formato der a formato pem que incluye la llave
	 * pública y el certificado y la escribe en la misma ruta en que se encuentre el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param certx509 File de la ubicación del certificado
	 * @return String con la ruta en la que se escribió el archivo .pem
	 */
	static String convertcerx509ToPEM(File certx509) {
		// Permite usar algoritmos de cifrado adicionales que no están en la implementación base de Java
		Security.addProvider(new BouncyCastleProvider());

		String outputhPath = certx509.getAbsolutePath().substring(0, certx509.getAbsolutePath().lastIndexOf("."))+ "_CER.pem";

		// 1. Leer DER y crear objeto x509 que lo contiene
		byte[] derBytes = null;
		try {
			derBytes = Files.readAllBytes(certx509.toPath());
		} catch (IOException e) {
			e.printStackTrace();
		}

		X509CertificateHolder certHolder = null;
		try {
			certHolder = new X509CertificateHolder(derBytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
		SubjectPublicKeyInfo publicKey = certHolder.getSubjectPublicKeyInfo();

		File outputPemFile = new File(outputhPath);
		// Escribe la llave pública y el certificado en formato PEM que de otra forma certHolder solo escribe el certificado
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(outputPemFile))) {
			pemWriter.writeObject(publicKey);
			pemWriter.writeObject(certHolder);
			System.out.println("Certificado PEM generado correctamente en: "+ outputhPath);
			return outputhPath;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Convierte una llave en formato pkcs8 con contraseña y su certificado con llave pública en formato der 
	 * a un archivo p12 o pfx con la misma contraseña y la escribe en la misma ruta en que se encuentre 
	 * el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param certx509 File de la ubicación del certificado
	 * @param oldPassword Es la contraseña para la llave FIEL
	 * @param newPassword Es la contraseña para el nuevo archovo p12 y su llave
	 * @param jks Indica con true que debe crearse un JKS en lugar de p12 o pfx
	 * @return String con la ruta en la que se escribió el archivo p12
	 */
	private static String createKSWithCertAndKey(File keypkcs8, File certx509, String oldPassword, String newPassword, Boolean jks) {
		String extension = (!jks) ? ".p12" : ".jks"; 
		String outputhPath = certx509.getAbsolutePath().substring(0, certx509.getAbsolutePath().lastIndexOf("."))+ extension;
		X509Certificate cert = loadCertificate(certx509);
		String RFC = getRFCFromCert(cert);
		PrivateKey privateKey = loadPrivateKey(keypkcs8, oldPassword);
		// Guardar el archivo PKCS12
		try (FileOutputStream fos = new FileOutputStream(outputhPath)) {
			// Inicializar el almacén de claves (vacío)
			KeyStore keyStore = (!jks) ?  KeyStore.getInstance("PKCS12", "BC") : KeyStore.getInstance("JKS");
			keyStore.load(null, null);
			String password = (newPassword == null) ? oldPassword : newPassword;
			keyStore.setKeyEntry(RFC, privateKey, password.toCharArray(),
					new java.security.cert.Certificate[] { cert });
			keyStore.store(fos, password.toCharArray());
			System.out.println("Keystore generado correctamente en: "+ outputhPath);
			return outputhPath;
		} catch (KeyStoreException e) {
			System.out.println("Error no coincide la contraseña con la llave\n");
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Convierte una llave en formato pkcs8 con contraseña y su certificado con llave pública en formato der 
	 * a un archivo p12 o pfx con la misma contraseña y la escribe en la misma ruta en que se encuentre 
	 * el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param certx509 File de la ubicación del certificado
	 * @param oldPassword Es la contraseña para la llave FIEL
	 * @param newPassword Es la contraseña para el nuevo archovo p12 y su llave
	 * @return String con la ruta en la que se escribió el archivo p12
	 */
	static String createPKCS12withCertAndKey(File keypkcs8, File certx509, String oldPassword, String newPassword) {
		return createKSWithCertAndKey(keypkcs8, certx509, oldPassword, newPassword, false);
	}
	
	/**
	 * Convierte una llave en formato pkcs8 con contraseña y su certificado con llave pública en formato der 
	 * a un archivo p12 o pfx con la misma contraseña y la escribe en la misma ruta en que se encuentre 
	 * el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param certx509 File de la ubicación del certificado
	 * @param password Es la contraseña para la llave FIEL
	 * @return String con la ruta en la que se escribió el archivo p12
	 */
	static String createPKCS12withCertAndKey(File keypkcs8, File certx509, String password) {
		return createKSWithCertAndKey(keypkcs8, certx509, password, null, false);
	}
	
	/**
	 * Convierte una llave en formato pkcs8 con contraseña y su certificado con llave pública en formato der 
	 * a un archivo JKS (Java Key Store) con la misma contraseña y la escribe en la misma ruta en que se encuentre 
	 * el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param certx509 File de la ubicación del certificado
	 * @param password Es la contraseña para la llave FIEL
	 * @return String con la ruta en la que se escribió el archivo p12
	 */
	static String createJKSwithCertAndKey(File keypkcs8, File certx509, String password) {
		return createKSWithCertAndKey(keypkcs8, certx509, password, null, true);
	}
	
	/**
	 * Convierte una llave en formato pkcs8 con contraseña y su certificado con llave pública en formato der 
	 * a un archivo JKS (Java Key Store) con la misma contraseña y la escribe en la misma ruta en que se encuentre 
	 * el archivo original
	 * Sirve para la Firma Electrónica FIEL del Sistema de Administración Tributaria SAT de México
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param certx509 File de la ubicación del certificado
	 * @param oldPassword Es la contraseña para la llave FIEL
	 * @param newPassword Es la contraseña para el nuevo archovo p12 y su llave
	 * @return String con la ruta en la que se escribió el archivo p12
	 */
	static String createJKSwithCertAndKey(File keypkcs8, File certx509, String oldPassword, String newPassword) {
		return createKSWithCertAndKey(keypkcs8, certx509, oldPassword, newPassword, true);
	}
	
	/**
	 * Genera un objeto PrivateKey a partir de una llave en formato PKCS8 con contraseña
	 * @param keypkcs8 File de la ubicación de la llave o .key
	 * @param password Es la contraseña para la llave FIEL
	 * @return PrivateKey representación del objeto llave para Java
	 */
	private static PrivateKey loadPrivateKey(File keypkcs8, String password) {
		// Permite usar algoritmos de cifrado adicionales que no están en la implementación base de Java
		Security.addProvider(new BouncyCastleProvider());
		// 1. Leer DER y crear objeto PKCS8EncryptedPrivateKeyInfo que lo contiene
		byte[] derBytes = null;
		try {
			derBytes = Files.readAllBytes(keypkcs8.toPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
		ASN1Sequence derseq = ASN1Sequence.getInstance(derBytes);
		PKCS8EncryptedPrivateKeyInfo encobj = new PKCS8EncryptedPrivateKeyInfo(
				EncryptedPrivateKeyInfo.getInstance(derseq));
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		
		InputDecryptorProvider decryptionProv;
		try {
			decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
			PrivateKeyInfo keyInfo = encobj.decryptPrivateKeyInfo(decryptionProv);
			PrivateKey privateKey = converter.getPrivateKey(keyInfo);
			return privateKey;
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (PKCSException e) {
			System.out.println("Error no coincide la contraseña con la llave\n");
			e.printStackTrace();
		} catch (PEMException e) {
			e.printStackTrace();
		}
		return null;
	}
    
	/**
	 * Genera un objeto X509Certificate a partir de una certificado en formato DER 
	 * con llave pública
	 * @param certFile File de la ubicación del certificado
	 * @return X509Certificate representación del objeto certificado para Java
	 */
    private static X509Certificate loadCertificate(File certFile) {
        FileInputStream fis = null;
		try {
			fis = new FileInputStream(certFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
        CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
	        X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);
	        fis.close();
	        return certificate;
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
    }
    
	/**
	 * Obtiene el identificado RFC (Registro Federal del Contribuyente) de un  
	 * certificado emitido por el SAT (Sistema de Administración Tributaria)
	 * @param X509Certificate representación del objeto certificado para Java
	 * @return String RFC identificador
	 */
    private static String getRFCFromCert(X509Certificate cert) {
		Map<String, String> knownOids = new HashMap<String, String>();
		knownOids.put("2.5.4.45", "uniqueIdentifier");
		String humanReadableDN = cert.getSubjectX500Principal().getName(X500Principal.RFC2253, knownOids);
		int idx = humanReadableDN.indexOf("uniqueIdentifier");
		String RFC = humanReadableDN.substring(idx + 17, idx + 30);
		return RFC;
    }

}
