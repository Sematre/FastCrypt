package de.sematre.fastcrypt;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;
import java.util.zip.CRC32;

public class FastChecksum {

	private static int bufferSize = 1024;

	public static long crc32(byte[] data) {
		CRC32 crc32 = new CRC32();
		crc32.update(data);
		return crc32.getValue();
	}

	public static long crc32(String data) {
		try {
			return crc32(data.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Is UTF-8 supported?", e);
		}
	}

	public static long crc32(InputStream inputStream) throws IOException {
		CRC32 crc32 = new CRC32();
		InputStream bufferedStream = new BufferedInputStream(inputStream);
		byte[] buffer = new byte[bufferSize];

		Integer available = -1;
		while ((available = bufferedStream.read(buffer)) != -1) {
			crc32.update(buffer, 0, available);
		}

		bufferedStream.close();
		return crc32.getValue();
	}

	public static long crc32(File file) throws IOException {
		return crc32(new FileInputStream(file));
	}

	public static long crc64(byte[] data) {
		CRC64 crc64 = new CRC64();
		crc64.update(data);
		return crc64.getValue();
	}

	public static long crc64(String data) {
		try {
			return crc64(data.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Is UTF-8 supported?", e);
		}
	}

	public static long crc64(InputStream inputStream) throws IOException {
		CRC64 crc64 = new CRC64();
		InputStream bufferedStream = new BufferedInputStream(inputStream);
		byte[] buffer = new byte[bufferSize];

		Integer available = -1;
		while ((available = bufferedStream.read(buffer)) != -1) {
			crc64.update(buffer, 0, available);
		}

		bufferedStream.close();
		return crc64.getValue();
	}

	public static long crc64(File file) throws IOException {
		return crc64(new FileInputStream(file));
	}

	public static long adler32(byte[] data) {
		Adler32 adler32 = new Adler32();
		adler32.update(data);
		return adler32.getValue();
	}

	public static long adler32(String data) {
		try {
			return adler32(data.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Is UTF-8 supported?", e);
		}
	}

	public static long adler32(InputStream inputStream) throws IOException {
		Adler32 adler32 = new Adler32();
		InputStream bufferedStream = new BufferedInputStream(inputStream);
		byte[] buffer = new byte[bufferSize];

		Integer available = -1;
		while ((available = bufferedStream.read(buffer)) != -1) {
			adler32.update(buffer, 0, available);
		}

		bufferedStream.close();
		return adler32.getValue();
	}

	public static long adler32(File file) throws IOException {
		return adler32(new FileInputStream(file));
	}

	public static long other(ChecksumAlgorithm algorithm, byte[] data) {
		switch (algorithm) {
			case CRC32:
				return crc32(data);

			case CRC64:
				return crc64(data);

			case ADLER32:
				return adler32(data);

			default:
				throw new RuntimeException("How did this happen?", new NoSuchAlgorithmException(algorithm + " is not implemented"));
		}
	}

	public static long other(ChecksumAlgorithm algorithm, String data) {
		try {
			return other(algorithm, data.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Is UTF-8 supported?", e);
		}
	}

	public static long other(ChecksumAlgorithm algorithm, InputStream inputStream) throws IOException {
		InputStream bufferedStream = new BufferedInputStream(inputStream);
		byte[] buffer = new byte[bufferSize];

		long value = -1;
		Integer available = -1;
		switch (algorithm) {
			case CRC32:
				CRC32 crc32 = new CRC32();
				while ((available = bufferedStream.read(buffer)) != -1) {
					crc32.update(buffer, 0, available);
				}

				value = crc32.getValue();
				break;

			case CRC64:
				CRC64 crc64 = new CRC64();
				while ((available = bufferedStream.read(buffer)) != -1) {
					crc64.update(buffer, 0, available);
				}

				value = crc64.getValue();
				break;

			case ADLER32:
				Adler32 adler32 = new Adler32();
				while ((available = bufferedStream.read(buffer)) != -1) {
					adler32.update(buffer, 0, available);
				}

				value = adler32.getValue();
				break;

			default:
				throw new RuntimeException("How did this happen?", new NoSuchAlgorithmException(algorithm + " is not implemented"));
		}

		bufferedStream.close();
		return value;
	}

	public static long other(ChecksumAlgorithm algorithm, File file) throws IOException {
		return other(algorithm, new FileInputStream(file));
	}

	public enum ChecksumAlgorithm {

		CRC32(null), CRC64(null), ADLER32(null);

		private Boolean defaultAlgorithm = null;

		private ChecksumAlgorithm(Boolean defaultAlgorithm) {
			this.defaultAlgorithm = defaultAlgorithm;
		}

		public Boolean isDefaultAlgorithm() {
			return defaultAlgorithm;
		}
	}

	public static class CRC64 {

		private Long poly = 0xC96C5795D7870F42L;
		private long[] table = new long[256];

		private long crc = -1;

		public CRC64() {
			for (Integer b = 0; b < table.length; b++) {
				Long r = b.longValue();
				for (Integer i = 0; i < 8; i++) {
					if ((r & 1) == 1) r = (r >>> 1) ^ poly;
					else r >>>= 1;
				}

				table[b] = r;
			}
		}

		public void update(byte b) {
			crc = table[(b ^ (int) crc) & 0xFF] ^ (crc >>> 8);
		}

		public void update(byte[] buf) {
			update(buf, 0, buf.length);
		}

		public void update(byte[] buf, int off, int len) {
			Integer end = off + len;
			while (off < end) {
				crc = table[(buf[off++] ^ (int) crc) & 0xFF] ^ (crc >>> 8);
			}
		}

		public void reset() {
			crc = -1;
		}

		public long getValue() {
			return ~crc;
		}
	}
}