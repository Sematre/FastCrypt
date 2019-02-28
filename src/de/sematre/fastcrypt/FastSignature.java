package de.sematre.fastcrypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class FastSignature {

	public static byte[] sign(String algorithm, byte[] data, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		Signature signature = Signature.getInstance(algorithm);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	public static Boolean verify(String algorithm, byte[] data, byte[] dataSignature, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		Signature signature = Signature.getInstance(algorithm);
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(dataSignature);
	}

	public static byte[] sign(SignatureAlgorithm algorithm, byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException {
		try {
			return sign(algorithm.getAlgorithm(), data, privateKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static Boolean verify(SignatureAlgorithm algorithm, byte[] data, byte[] dataSignature, PublicKey publicKey) throws InvalidKeyException, SignatureException {
		try {
			return verify(algorithm.getAlgorithm(), data, dataSignature, publicKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public enum SignatureAlgorithm {

		NONEwithRSA("NONEwithRSA", true),
		MD2withRSA("MD2withRSA", true),
		MD5withRSA("MD5withRSA", true),
		SHA1withRSA("SHA1withRSA", true),
		SHA224withRSA("SHA224withRSA", true),
		SHA256withRSA("SHA256withRSA", true),
		SHA384withRSA("SHA384withRSA", true),
		SHA512withRSA("SHA512withRSA", true),
		NONEwithDSA("NONEwithDSA", true),
		SHA1withDSA("SHA1withDSA", true),
		SHA224withDSA("SHA224withDSA", true),
		SHA256withDSA("SHA256withDSA", true),
		SHA384withDSA("SHA384withDSA", true),
		SHA512withDSA("SHA512withDSA", true),
		NONEwithECDSA("NONEwithECDSA", true),
		SHA1withECDSA("SHA1withECDSA", true),
		SHA224withECDSA("SHA224withECDSA", true),
		SHA256withECDSA("SHA256withECDSA", true),
		SHA384withECDSA("SHA384withECDSA", true),
		SHA512withECDSA("SHA512withECDSA", true);

		private String algorithm = null;
		private Boolean defaultAlgorithm = null;

		private SignatureAlgorithm(String algorithm, Boolean defaultAlgorithm) {
			this.algorithm = algorithm;
			this.defaultAlgorithm = defaultAlgorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public Boolean isDefaultAlgorithm() {
			return defaultAlgorithm;
		}

		public static SignatureAlgorithm getSignatureAlgorithm(String algorithm) {
			for (SignatureAlgorithm signatureAlgorithm : values()) {
				if (signatureAlgorithm.getAlgorithm().equalsIgnoreCase(algorithm)) return signatureAlgorithm;
			}

			return null;
		}
	}
}