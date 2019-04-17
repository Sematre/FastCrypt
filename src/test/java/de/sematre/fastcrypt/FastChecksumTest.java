package de.sematre.fastcrypt;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class FastChecksumTest {

	private String file5MB = "5MB.zip";

	@Test
	public void testCrc32() throws Exception {
		assertEquals(3068527472L, FastChecksum.crc32(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testCrc64() throws Exception {
		assertEquals(-8868427914496118327L, FastChecksum.crc64(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testAdler32() throws Exception {
		assertEquals(268939623L, FastChecksum.adler32(getClass().getResourceAsStream("/" + file5MB)));
	}
}