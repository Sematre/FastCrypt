package de.sematre.fastcrypt;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class FastHashTest {

	private String file5MB = "5MB.zip";

	@Test
	public void testMd2() throws Exception {
		assertEquals("315f7c67223f01fb7cab4b95100e872e", FastHash.md2("Hello World!"));
		assertEquals("11e91a10c46ee0ac321d0dd6995f60b3", FastHash.md2(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testMd5() throws Exception {
		assertEquals("ed076287532e86365e841e92bfc50d8c", FastHash.md5("Hello World!"));
		assertEquals("b3215c06647bc550406a9c8ccc378756", FastHash.md5(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testSha1() throws Exception {
		assertEquals("2ef7bde608ce5404e97d5f042f95f89f1c232871", FastHash.sha1("Hello World!"));
		assertEquals("0cc897be1958c0f44371a8ff3dddbc092ff530d0", FastHash.sha1(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testSha224() throws Exception {
		assertEquals("4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b", FastHash.sha224("Hello World!"));
		assertEquals("aaa3d5ee1a61828cf879e77eb68ec63430a7e0fa00148774dc8667ec", FastHash.sha224(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testSha256() throws Exception {
		assertEquals("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", FastHash.sha256("Hello World!"));
		assertEquals("c0de104c1e68625629646025d15a6129a2b4b6496cd9ceacd7f7b5078e1849ba", FastHash.sha256(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testSha384() throws Exception {
		assertEquals("bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a", FastHash.sha384("Hello World!"));
		assertEquals("bb38381f504f66229b175b9610a18ac7e3a4e050372fd46af0dfffe3bfb544d613f344b5320ae2ee74722513b71b32a5", FastHash.sha384(getClass().getResourceAsStream("/" + file5MB)));
	}

	@Test
	public void testSha512() throws Exception {
		assertEquals("861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8", FastHash.sha512("Hello World!"));
		assertEquals("ce317cfb7e012396b3320ebbef302661b9e25ec903ff69a27cb20ef702417b2ec3884e0cf9b72e3290f0a8a15db398139e35b35c426f6a91793c3ba99ba0b8c3", FastHash.sha512(getClass().getResourceAsStream("/" + file5MB)));
	}
}