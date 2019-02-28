package de.sematre.fastcrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.spec.SecretKeySpec;

public class KeyUtils {

	public static void exportKey(Key key, File file) {
		try {
			PrintWriter pw = new PrintWriter(file);
			pw.println(key.getAlgorithm());
			pw.print(Base64.getEncoder().encodeToString(key.getEncoded()));
			pw.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static Key importKey(File file) {
		try {
			Scanner scanner = new Scanner(file);
			String algorithm = scanner.nextLine();
			byte[] encoded = Base64.getDecoder().decode(scanner.nextLine());
			scanner.close();

			return new SecretKeySpec(encoded, algorithm);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void exportKeyPair(KeyPair keyPair, File file) {
		try {
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());

			PrintWriter pw = new PrintWriter(file);
			pw.println("RSA KeyPair");
			pw.println(Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded()));
			pw.print(Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded()));
			pw.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static KeyPair importKeyPair(File file) {
		try {
			Scanner scanner = new Scanner(file);
			if (!scanner.nextLine().equals("RSA KeyPair")) {
				scanner.close();
				throw new IllegalArgumentException("Invalid key file!");
			}

			byte[] privateKey = Base64.getDecoder().decode(scanner.nextLine());
			byte[] publicKey = Base64.getDecoder().decode(scanner.nextLine());
			scanner.close();

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(publicKey)), keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void exportPublicKey(PublicKey key, File file) {
		try {
			PrintWriter pw = new PrintWriter(file);
			pw.println("RSA PublicKey");
			pw.print(Base64.getEncoder().encodeToString(new X509EncodedKeySpec(key.getEncoded()).getEncoded()));
			pw.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static PublicKey importPublicKey(File file) {
		try {
			Scanner scanner = new Scanner(file);
			if (!scanner.nextLine().equals("RSA PublicKey")) {
				scanner.close();
				throw new IllegalArgumentException("Invalid key file!");
			}

			byte[] encoded = Base64.getDecoder().decode(scanner.nextLine());
			scanner.close();

			return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void exportPrivateKey(PrivateKey key, File file) {
		try {
			PrintWriter pw = new PrintWriter(file);
			pw.println("RSA PrivateKey");
			pw.print(Base64.getEncoder().encodeToString(new PKCS8EncodedKeySpec(key.getEncoded()).getEncoded()));
			pw.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static PrivateKey importPrivateKey(File file) {
		try {
			Scanner scanner = new Scanner(file);
			if (!scanner.nextLine().equals("RSA PrivateKey")) {
				scanner.close();
				throw new IllegalArgumentException("Invalid key file!");
			}

			byte[] encoded = Base64.getDecoder().decode(scanner.nextLine());
			scanner.close();

			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static Certificate importCertificate(File file) {
		try {
			return CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(file));
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		}
	}
}