package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Notice;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class Base64ValueTest {

	@Test
	public void testIllegalDecodedSize() {
		ArrayList<Notice> notices = new ArrayList<>();

		Parser.parse("script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding).",
				notices.get(0).show());

		notices.clear();
		Parser.parse("script-src 'self' 'sha256-YWFmMzU3YWU0ZDYzM2IzYWEzZTIzOTg2Yjk1ZGFjYWQ2Yzg_ZDdhZDM4MTAyZWUwMjNmZjk5M2IwNW-zN2RkOA==' https://example.com",
				"https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals(
				"Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation.",
				notices.get(0).show());
	}

	@Test
	public void testIllegalLength() {
		ArrayList<Notice> notices = new ArrayList<>();

		Parser.parse("script-src 'self' https://example.com 'nonce-/9j/4AAQSkZJRgABAQAA'", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding).",
				notices.get(0).show());

		notices.clear();
		Parser.parse("script-src 'self' https://example.com 'nonce-'", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals("Invalid base64-value (too short: 0).", notices.get(0).show());

		notices.clear();
		Parser.parse("script-src 'self' https://example.com 'nonce-abc'", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals(
				"Invalid base64-value (should be multiple of 4 bytes: 3).",
				notices.get(0).show());
	}

	@Test
	public void testIllegalChars() {
		ArrayList<Notice> notices = new ArrayList<>();

		Parser.parse("script-src 'self' https://example.com 'nonce-12rwf5tegfszeq23ewv4cgefw43^'", "https://origin",
				notices);
		assertEquals(1, notices.size());
		assertEquals(
				"Invalid base64-value (characters are not in the base64-value grammar).",
				notices.get(0).show());

		notices.clear();
		Parser.parse("script-src 'self' https://example.com 'nonce-1^=='", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals(
				"Invalid base64-value (characters are not in the base64-value grammar).",
				notices.get(0).show());

		notices.clear();
		Parser.parse("script-src 'self' https://example.com 'nonce-12_/-+=='", "https://origin", notices);
		assertEquals(2, notices.size());
		assertEquals(
				"Invalid base64-value. Must use either RFC4648 \"base64\" characters (including + and /) or RFC4648 \"base64url\" characters (including - and _), but not both.",
				notices.get(0).show());
		assertEquals(
				"CSP specification recommends nonce-value to be at least 128 bits long (before encoding).",
				notices.get(1).show());

		Parser.parse("script-src 'self' https://example.com 'nonce-12-+/'", "https://origin", notices);
		assertEquals(3, notices.size());
		assertEquals(
				"Invalid base64-value. Must use either RFC4648 \"base64\" characters (including + and /) or RFC4648 \"base64url\" characters (including - and _), but not both.",
				notices.get(0).show());
		assertEquals(
				"CSP specification recommends nonce-value to be at least 128 bits long (before encoding).",
				notices.get(1).show());
		assertEquals(
				"Invalid base64-value (should be multiple of 4 bytes: 5).",
				notices.get(2).show());
	}

	@Test
	public void testIllegalPadding() {
		ArrayList<Notice> notices = new ArrayList<>();

		Parser.parse("script-src 'self' https://example.com 'nonce-12=+'", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals(
				"Invalid base64-value padding (illegal characters).",
				notices.get(0).show());

		notices.clear();
		Parser.parse("script-src 'self' https://example.com 'nonce-1==='", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals(
				"Invalid base64-value (bad padding).",
				notices.get(0).show());
	}

	@Test
	public void testMultipleWarnings() {
		ArrayList<Notice> notices = new ArrayList<>();

		Parser.parse("script-src 'self' https://example.com 'nonce-31231asda_dsdsxc'", "https://origin", notices);
		assertEquals(1, notices.size());
		assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding).",
				notices.get(0).show());

	}

	@Test
	public void testValid() {

		for (int i = 16; i <= 32; i++) {
			byte[] b = new byte[i];
			new Random().nextBytes(b);
			String encoded = Base64.getEncoder().encodeToString(b);
			ArrayList<Notice> notices = new ArrayList<>();

			Parser.parse("script-src 'self' https://example.com 'nonce-" + encoded + "'",
					"https://origin", notices);
			assertEquals(0, notices.size());
		}

		for (int i = 16; i <= 32; i++) {
			byte[] b = new byte[i];
			new Random().nextBytes(b);
			String encoded = Base64.getUrlEncoder().encodeToString(b);
			ArrayList<Notice> notices = new ArrayList<>();

			Parser.parse("script-src 'self' https://example.com 'nonce-" + encoded + "'",
					"https://origin", notices);
			assertEquals(0, notices.size());

		}

	}
}
