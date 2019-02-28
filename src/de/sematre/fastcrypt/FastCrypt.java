package de.sematre.fastcrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

public class FastCrypt {

	/**
	 * Generate an RSA <i>KeyPair</i> instance.
	 */
	public static KeyPair generateKeyPair() {
		try {
			return KeyPairGenerator.getInstance("RSA").generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate an RSA <i>KeyPair</i> instance.
	 * @param keySize Size of the key pair
	 */
	public static KeyPair generateKeyPair(Integer keySize) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keySize, new SecureRandom());
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate an RSA <i>KeyPair</i> instance.
	 * @param keySize Size of the key pair
	 * @param seed The seed
	 */
	public static KeyPair generateKeyPair(Integer keySize, byte[] seed) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keySize, new SecureRandom(seed));
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate an RSA <i>KeyPair</i> instance.
	 * @param keySize Size of the key pair
	 * @param seed UTF-8 encoded seed
	 */
	public static KeyPair generateKeyPair(Integer keySize, String seed) {
		try {
			return generateKeyPair(keySize, seed.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 */
	public static Key generateKey(String algorithm) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance(algorithm);
		generator.init(new SecureRandom());
		return generator.generateKey();
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param keySize The size of the key
	 */
	public static Key generateKey(String algorithm, Integer keySize) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance(algorithm);
		generator.init(keySize, new SecureRandom());
		return generator.generateKey();
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param seed The seed
	 */
	public static Key generateKey(String algorithm, byte[] seed) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance(algorithm);
		generator.init(new SecureRandom(seed));
		return generator.generateKey();
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param seed UTF-8 encoded seed
	 */
	public static Key generateKey(String algorithm, String seed) throws NoSuchAlgorithmException {
		try {
			return generateKey(algorithm, seed.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param keySize The size of the key
	 * @param seed The seed
	 */
	public static Key generateKey(String algorithm, Integer keySize, byte[] seed) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance(algorithm);
		generator.init(keySize, new SecureRandom(seed));
		return generator.generateKey();
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param keySize The size of the key
	 * @param seed UTF-8 encoded seed
	 */
	public static Key generateKey(String algorithm, Integer keySize, String seed) throws NoSuchAlgorithmException {
		try {
			return generateKey(algorithm, keySize, seed.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 */
	public static Key generateKey(KeyAlgorithm keyAlgorithm) {
		try {
			return generateKey(keyAlgorithm.getAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param keySize The size of the key
	 */
	public static Key generateKey(KeyAlgorithm keyAlgorithm, Integer keySize) {
		try {
			return generateKey(keyAlgorithm.getAlgorithm(), keySize);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param seed The seed
	 */
	public static Key generateKey(KeyAlgorithm keyAlgorithm, byte[] seed) {
		try {
			return generateKey(keyAlgorithm.getAlgorithm(), seed);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param seed UTF-8 encoded seed
	 */
	public static Key generateKey(KeyAlgorithm keyAlgorithm, String seed) {
		try {
			return generateKey(keyAlgorithm.getAlgorithm(), seed);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param keySize The size of the key
	 * @param seed The seed
	 */
	public static Key generateKey(KeyAlgorithm keyAlgorithm, Integer keySize, byte[] seed) {
		try {
			return generateKey(keyAlgorithm.getAlgorithm(), keySize, seed);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate a <i>Key</i> instance.
	 * @param algorithm The key algorithm
	 * @param keySize The size of the key
	 * @param seed UTF-8 encoded seed
	 */
	public static Key generateKey(KeyAlgorithm keyAlgorithm, Integer keySize, String seed) {
		try {
			return generateKey(keyAlgorithm.getAlgorithm(), keySize, seed);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Encrypts a serializable <i>Object</i> into an <i>byte[]</i>.
	 * @param cipher The cipher instance
	 * @param object The serializable <i>Object</i>
	 * @return The encrypted object as <i>byte[]</i>
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] encryptObject(Cipher cipher, Object object) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
		objectStream.writeObject(object);
		objectStream.flush();
		objectStream.close();
		byte[] bytes = byteStream.toByteArray();
		byteStream.close();
		return cipher.doFinal(bytes);
	}

	/**
	 * Encrypts a serializable <i>Object</i> into an <i>byte[]</i>.
	 * @param key The key instance
	 * @param object The serializable <i>Object</i>
	 * @return The encrypted object as <i>byte[]</i>
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] encryptObject(Key key, Object object) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
		objectStream.writeObject(object);
		objectStream.flush();
		objectStream.close();
		byte[] bytes = byteStream.toByteArray();
		byteStream.close();
		return encryptData(key, bytes);
	}

	/**
	 * Decrypts a <i>byte[]</i> into an <i>Object</i>.
	 * @param cipher The cipher instance
	 * @param data The encrypted data
	 * @return The decrypted <i>byte[]</i> as <i>Object<i>
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static Object decryptObject(Cipher cipher, byte[] data) throws IOException, ClassNotFoundException, BadPaddingException, IllegalBlockSizeException {
		ByteArrayInputStream byteStream = new ByteArrayInputStream(cipher.doFinal(data));
		ObjectInputStream objectStream = new ObjectInputStream(byteStream);
		Object object = objectStream.readObject();
		objectStream.close();
		byteStream.close();
		return object;
	}

	/**
	 * Decrypts a <i>byte[]</i> into an <i>Object</i>.
	 * @param key The key instance
	 * @param data The encrypted data
	 * @return The decrypted <i>byte[]</i> as <i>Object<i>
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Object decryptObject(Key key, byte[] data) throws IOException, ClassNotFoundException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		ByteArrayInputStream byteStream = new ByteArrayInputStream(decryptData(key, data));
		ObjectInputStream objectStream = new ObjectInputStream(byteStream);
		Object object = objectStream.readObject();
		objectStream.close();
		byteStream.close();
		return object;
	}

	/**
	 * Encrypts a <i>byte[]</i>.
	 * @param key The key instance
	 * @param data The raw data
	 * @return The encrypted <i>byte[]</i>
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] encryptData(Key key, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createEncryptCipher(key, key.getAlgorithm()).doFinal(data);
	}

	/**
	 * Encrypts a <i>byte[]</i>.
	 * @param key The key instance
	 * @param algorithm The encrypt algorithm
	 * @param data The raw data
	 * @return The encrypted <i>byte[]</i>
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] encryptData(Key key, String algorithm, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createEncryptCipher(key, algorithm).doFinal(data);
	}

	/**
	 * Encrypts a <i>byte[]</i>.
	 * @param key The key instance
	 * @param algorithm The encrypt algorithm
	 * @param data The raw data
	 * @return The encrypted <i>byte[]</i>
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] encryptData(Key key, CipherAlgorithm algorithm, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createEncryptCipher(key, algorithm).doFinal(data);
	}

	/**
	 * Decrypts a <i>byte[]</i>.
	 * @param key The key instance
	 * @param data The encrypted data
	 * @return The decrypted <i>byte[]</i>
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] decryptData(Key key, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createDecryptCipher(key, key.getAlgorithm()).doFinal(data);
	}

	/**
	 * Decrypts a <i>byte[]</i>.
	 * @param key The key instance
	 * @param algorithm The decrypt algorithm
	 * @param data The encrypted data
	 * @return The decrypted <i>byte[]</i>
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] decryptData(Key key, String algorithm, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createDecryptCipher(key, algorithm).doFinal(data);
	}

	/**
	 * Decrypts a <i>byte[]</i>.
	 * @param key The key instance
	 * @param algorithm The decrypt algorithm
	 * @param data The encrypted data
	 * @return The decrypted <i>byte[]</i>
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] decryptData(Key key, CipherAlgorithm algorithm, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createDecryptCipher(key, algorithm).doFinal(data);
	}

	/**
	 * Execute an <i>Cipher</i> operation.
	 * @param cipher The cipher instance
	 * @param data The raw data
	 * @return The operation result
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] cipherOperation(Cipher cipher, byte[] data) throws IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(data);
	}

	/**
	 * Hashs an <i>byte[]</i>.
	 * @param mac The mac instance
	 * @param data The raw data
	 * @return The hashed <i>byte[]</i>
	 */
	public static byte[] macOperation(Mac mac, byte[] data) {
		return mac.doFinal(data);
	}

	/**
	 * Create an encryption <i>Cipher</i>.
	 * @param key The key instance
	 * @param algorithm The algorithm
	 * @return The cipher instance
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Cipher createEncryptCipher(Key key, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createCipher(Cipher.ENCRYPT_MODE, algorithm, key);
	}

	/**
	 * Create an encryption <i>Cipher</i>.
	 * @param key The key instance
	 * @param algorithm The algorithm
	 * @return The cipher instance
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Cipher createEncryptCipher(Key key, CipherAlgorithm algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createCipher(Cipher.ENCRYPT_MODE, algorithm, key);
	}

	/**
	 * Create an decryption <i>Cipher</i>.
	 * @param key The key instance
	 * @param algorithm The algorithm
	 * @return The cipher instance
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Cipher createDecryptCipher(Key key, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createCipher(Cipher.DECRYPT_MODE, algorithm, key);
	}

	/**
	 * Create an decryption <i>Cipher</i>.
	 * @param key The key instance
	 * @param algorithm The algorithm
	 * @return The cipher instance
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Cipher createDecryptCipher(Key key, CipherAlgorithm algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		return createCipher(Cipher.DECRYPT_MODE, algorithm, key);
	}

	/**
	 * Create an <i>Cipher</i> instance.
	 * @param operation <i>Cipher.ENCRYPT_MODE</i> or <i>Cipher.DECRYPT_MODE</i>
	 * @param algorithm The algorithm
	 * @param key The key instance
	 * @return The cipher instance
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 */
	public static Cipher createCipher(Integer operation, String algorithm, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(operation, key);
		return cipher;
	}

	/**
	 * Create an cipher instance.
	 * @param operation <i>Cipher.ENCRYPT_MODE</i> or <i>Cipher.DECRYPT_MODE</i>
	 * @param algorithm The algorithm
	 * @param key The key instance
	 * @return The cipher instance
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 */
	public static Cipher createCipher(Integer operation, CipherAlgorithm algorithm, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		return createCipher(operation, algorithm.getAlgorithm(), key);
	}

	/**
	 * Create an <i>Mac</i> instance.
	 * @param algorithm The algorithm
	 * @param key The key instance
	 * @return The mac instance
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static Mac createMac(String algorithm, Key key) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(algorithm);
		mac.init(key);
		return mac;
	}

	/**
	 * Create an <i>Mac</i> instance.
	 * @param algorithm The algorithm
	 * @param key The key instance
	 * @return The mac instance
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static Mac createMac(MacAlgorithm algorithm, Key key) throws NoSuchAlgorithmException, InvalidKeyException {
		return createMac(algorithm.getAlgorithm(), key);
	}

	/**
	 * Create an <i>Mac</i> instance.
	 * @param key The key instance
	 * @return The mac instance
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static Mac createMac(Key key) throws NoSuchAlgorithmException, InvalidKeyException {
		return createMac(key.getAlgorithm(), key);
	}

	/**
	 * Generate an random <i>String</i>.
	 * @param size The string length
	 * @param allowedChars The allowed chars
	 * @return The ganerated String
	 */
	public static String generateRandomString(Integer size, String allowedChars) {
		SecureRandom random = new SecureRandom();
		StringBuilder builder = new StringBuilder(size);
		for (Integer index = 0; index < size; index++) {
			builder.append(allowedChars.charAt(random.nextInt(allowedChars.length())));
		}

		return builder.toString();
	}

	/**
	 * Generate an random <i>String</i>. Default chars: A-Z, a-z, 0-9
	 * @param size The string length
	 * @return The ganerated String
	 */
	public static String generateRandomString(Integer size) {
		return generateRandomString(size, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890");
	}

	/**
	 * Encode an <i>byte[]</i> into a <i>String</i>
	 * @param data The byte[]
	 * @return The base64 string
	 */
	public static String encodeBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	/**
	 * Decode an <i>String</i> into a <i>byte[]</i>
	 * @param data The encoded String
	 * @return The decoded byte[]
	 */
	public static byte[] decodeBase64(String data) {
		return Base64.getDecoder().decode(data);
	}

	/**
	 * Convert an <i>byte[]</i> into an hex <i>String</i>
	 * @param input The byte[]
	 * @return The hex string
	 */
	public static String byteArrayToHexString(byte[] input) {
		char[] chars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

		Integer length = input.length;
		char[] bytes = new char[length << 1];
		for (Integer arrayIndex = 0, index = 0; index < length; index++) {
			bytes[arrayIndex++] = chars[((0xF0 & input[index]) >>> 4)];
			bytes[arrayIndex++] = chars[(0xF & input[index])];
		}

		return new String(bytes);
	}

	/**
	 * Convert an hex <i>String</i> into an <i>byte[]</i>
	 * @param input The hex string
	 * @return The byte[]
	 */
	public static byte[] hexStringToByteArray(String input) {
		input = input.toUpperCase();
		byte[] bytes = new byte[input.length() / 2];
		for (Integer arrayIndex = 0; arrayIndex < bytes.length; arrayIndex++) {
			Integer index = arrayIndex * 2;
			bytes[arrayIndex] = (byte) Integer.parseInt(input.substring(index, index + 2), 16);
		}

		return bytes;
	}

	/**
	 * Convert an <i>byte</i> into an bin <i>String</i>
	 * @param input The byte
	 * @return The bin string
	 */
	public static String byteToBinString(byte input) {
		return String.format("%8s", Integer.toBinaryString(input & 0xFF)).replace(' ', '0');
	}

	/**
	 * Convert an <i>byte[]</i> into an bin <i>String</i>
	 * @param input The byte[]
	 * @return The bin string
	 */
	public static String byteArrayToBinString(byte[] input) {
		String data = "";
		for (byte part : input) {
			data += byteToBinString(part);
		}

		return data;
	}

	/**
	 * Convert an <i>Key</i> into an hex <i>String</i>
	 * @param key The key instance
	 * @return The hex string
	 */
	public static String keyToHexString(Key key) {
		return byteArrayToHexString(key.getEncoded());
	}

	/**
	 * Convert an <i>Key</i> into an arduino <i>String</i>
	 * @param key The key instance
	 * @return The arduino string
	 */
	public static String keyToArduinoString(Key key) {
		char[] chars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

		String output = "";
		byte[] data = key.getEncoded();
		for (Integer index = 0; index < data.length; index++) {
			byte part = data[index];
			output += "0x" + chars[((0xF0 & part) >>> 4)] + chars[(0xF & part)] + (index + 1 < data.length ? ", " : "");
		}

		return "{" + output + "}";
	}

	/**
	 * Key algorithms
	 *
	 */
	public enum KeyAlgorithm {

		AES("AES", true),
		ARCFOUR("ARCFOUR", false),
		Blowfish("Blowfish", false),
		DES("DES", true),
		DESede("DESede", true),
		HmacMD5("HmacMD5", false),
		HmacSHA1("HmacSHA1", true),
		HmacSHA256("HmacSHA256", true),
		HmacSHA384("HmacSHA384", false),
		HmacSHA512("HmacSHA512", false),
		RC2("RC2", false),
		RC4("RC4", false);

		private String algorithm = null;
		private Boolean defaultAlgorithm = null;

		private KeyAlgorithm(String algorithm, Boolean defaultAlgorithm) {
			this.algorithm = algorithm;
			this.defaultAlgorithm = defaultAlgorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public Boolean isDefaultAlgorithm() {
			return defaultAlgorithm;
		}

		public static KeyAlgorithm getKeyAlgorithm(String algorithm) {
			for (KeyAlgorithm keyAlgorithm : values()) {
				if (keyAlgorithm.getAlgorithm().equalsIgnoreCase(algorithm)) return keyAlgorithm;
			}

			return null;
		}
	}

	/**
	 * Cipher algorithms
	 *
	 */
	public enum CipherAlgorithm {

		AES("AES", true),
		AES_CBC_NoPadding("AES/CBC/NOPADDING", true),
		AES_CBC_PKCS5Padding("AES/CBC/PKCS5PADDING", true),
		AES_ECB_NoPadding("AES/ECB/NOPADDING", true),
		AES_ECB_PKCS5Padding("AES/ECB/PKCS5PADDING", true),
		DES_CBC_NoPadding("DES/CBC/NOPADDING", true),
		DES_CBC_PKCS5Padding("DES/CBC/PKCS5PADDING", true),
		DES_ECB_NoPadding("DES/ECB/NOPADDING", true),
		DES_ECB_PKCS5Padding("DES/ECB/PKCS5PADDING", true),
		DESede_CBC_NoPadding("DESEDE/CBC/NOPADDING", true),
		DESede_CBC_PKCS5Padding("DESEDE/CBC/PKCS5PADDING", true),
		DESede_ECB_NoPadding("DESEDE/ECB/NOPADDING", true),
		DESede_ECB_PKCS5Padding("DESEDE/ECB/PKCS5PADDING", true),
		RSA("RSA", true),
		RSA_ECB_PKCS1Padding("RSA/ECB/PKCS1PADDING", true),
		RSA_ECB_OAEPWithSHA_1_AndMGF1Padding("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING", true),
		RSA_ECB_OAEPWithSHA_256_AndMGF1Padding("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", true),
		RC2("RC2", false),
		RC4("RC4", false);

		private String algorithm = null;
		private Boolean defaultAlgorithm = null;

		private CipherAlgorithm(String algorithm, Boolean defaultAlgorithm) {
			this.algorithm = algorithm;
			this.defaultAlgorithm = defaultAlgorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public Boolean isDefaultAlgorithm() {
			return defaultAlgorithm;
		}

		public static CipherAlgorithm getCipherAlgorithm(String algorithm) {
			for (CipherAlgorithm cipherAlgorithm : values()) {
				if (cipherAlgorithm.getAlgorithm().equalsIgnoreCase(algorithm)) return cipherAlgorithm;
			}

			return null;
		}
	}

	/**
	 * Mac algorithms
	 *
	 */
	public enum MacAlgorithm {

		HmacMD5("HmacMD5", false),
		HmacSHA1("HmacSHA1", true),
		HmacSHA256("HmacSHA256", true),
		HmacSHA384("HmacSHA384", false),
		HmacSHA512("HmacSHA512", false);

		private String algorithm = null;
		private Boolean defaultAlgorithm = null;

		private MacAlgorithm(String algorithm, Boolean defaultAlgorithm) {
			this.algorithm = algorithm;
			this.defaultAlgorithm = defaultAlgorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public Boolean isDefaultAlgorithm() {
			return defaultAlgorithm;
		}

		public static MacAlgorithm getMacAlgorithm(String algorithm) {
			for (MacAlgorithm macAlgorithm : values()) {
				if (macAlgorithm.getAlgorithm().equalsIgnoreCase(algorithm)) return macAlgorithm;
			}

			return null;
		}
	}
}