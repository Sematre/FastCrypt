package de.sematre.fastcrypt;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FastByteHash {

	private static int bufferSize = 1024;

	public static byte[] md2(String text) {
		return other(HashAlgorithm.MD2, text);
	}

	public static byte[] md5(String text) {
		return other(HashAlgorithm.MD5, text);
	}

	public static byte[] sha1(String text) {
		return other(HashAlgorithm.SHA1, text);
	}

	public static byte[] sha224(String text) {
		return other(HashAlgorithm.SHA224, text);
	}

	public static byte[] sha256(String text) {
		return other(HashAlgorithm.SHA256, text);
	}

	public static byte[] sha384(String text) {
		return other(HashAlgorithm.SHA384, text);
	}

	public static byte[] sha512(String text) {
		return other(HashAlgorithm.SHA512, text);
	}

	public static byte[] md2(byte[] data) {
		return other(HashAlgorithm.MD2, data);
	}

	public static byte[] md5(byte[] data) {
		return other(HashAlgorithm.MD5, data);
	}

	public static byte[] sha1(byte[] data) {
		return other(HashAlgorithm.SHA1, data);
	}

	public static byte[] sha224(byte[] data) {
		return other(HashAlgorithm.SHA224, data);
	}

	public static byte[] sha256(byte[] data) {
		return other(HashAlgorithm.SHA256, data);
	}

	public static byte[] sha384(byte[] data) {
		return other(HashAlgorithm.SHA384, data);
	}

	public static byte[] sha512(byte[] data) {
		return other(HashAlgorithm.SHA512, data);
	}

	public static byte[] md2(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.MD2, inputStream);
	}

	public static byte[] md5(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.MD5, inputStream);
	}

	public static byte[] sha1(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.SHA1, inputStream);
	}

	public static byte[] sha224(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.SHA224, inputStream);
	}

	public static byte[] sha256(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.SHA256, inputStream);
	}

	public static byte[] sha384(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.SHA384, inputStream);
	}

	public static byte[] sha512(InputStream inputStream) throws IOException {
		return other(HashAlgorithm.SHA512, inputStream);
	}

	public static byte[] md2(File file) throws IOException {
		return other(HashAlgorithm.MD2, file);
	}

	public static byte[] md5(File file) throws IOException {
		return other(HashAlgorithm.MD5, file);
	}

	public static byte[] sha1(File file) throws IOException {
		return other(HashAlgorithm.SHA1, file);
	}

	public static byte[] sha224(File file) throws IOException {
		return other(HashAlgorithm.SHA224, file);
	}

	public static byte[] sha256(File file) throws IOException {
		return other(HashAlgorithm.SHA256, file);
	}

	public static byte[] sha384(File file) throws IOException {
		return other(HashAlgorithm.SHA384, file);
	}

	public static byte[] sha512(File file) throws IOException {
		return other(HashAlgorithm.SHA512, file);
	}

	public static byte[] other(String algorithm, String data) throws NoSuchAlgorithmException {
		try {
			return other(algorithm, data.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] other(String algorithm, byte[] data) throws NoSuchAlgorithmException {
		return MessageDigest.getInstance(algorithm).digest(data);
	}

	public static byte[] other(HashAlgorithm algorithm, byte[] data) {
		try {
			return other(algorithm.getAlgorithm(), data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] other(HashAlgorithm algorithm, String data) {
		try {
			return other(algorithm.getAlgorithm(), data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] other(String algorithm, InputStream inputStream) throws NoSuchAlgorithmException, IOException {
		MessageDigest digest = MessageDigest.getInstance(algorithm);
		InputStream bufferedStream = new BufferedInputStream(inputStream);
		byte[] buffer = new byte[bufferSize];

		Integer available = -1;
		while ((available = bufferedStream.read(buffer)) != -1) {
			digest.update(buffer, 0, available);
		}

		bufferedStream.close();
		return digest.digest();
	}

	public static byte[] other(HashAlgorithm algorithm, InputStream inputStream) throws IOException {
		try {
			return other(algorithm.getAlgorithm(), inputStream);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] other(String algorithm, File file) throws NoSuchAlgorithmException, IOException {
		return other(algorithm, new FileInputStream(file));
	}

	public static byte[] other(HashAlgorithm algorithm, File file) throws IOException {
		try {
			return other(algorithm.getAlgorithm(), file);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public enum HashAlgorithm {

		MD2("MD2", null),
		MD5("MD5", null),
		SHA1("SHA-1", null),
		SHA224("SHA-224", null),
		SHA256("SHA-256", null),
		SHA384("SHA-384", null),
		SHA512("SHA-512", null);

		private String algorithm = null;
		private Boolean defaultAlgorithm = null;

		private HashAlgorithm(String algorithm, Boolean defaultAlgorithm) {
			this.algorithm = algorithm;
			this.defaultAlgorithm = defaultAlgorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public Boolean isDefaultAlgorithm() {
			return defaultAlgorithm;
		}

		public static HashAlgorithm getHashAlgorithm(String algorithm) {
			for (HashAlgorithm hashAlgorithm : values()) {
				if (hashAlgorithm.getAlgorithm().equalsIgnoreCase(algorithm)) return hashAlgorithm;
			}

			return null;
		}
	}
}