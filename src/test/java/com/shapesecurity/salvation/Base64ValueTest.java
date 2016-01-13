package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Notice;
import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class Base64ValueTest {

    @Test
    public void testIllegalDecodedSize() {
        ArrayList<Notice> notices = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding)", notices
            .get(0).show());

        notices.clear();
        Parser.parse("script-src 'self' 'sha256-K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols=' https://example.com", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());
    }

    @Test
    public void testIllegalLength() {
        ArrayList<Notice> notices = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-/9j/4AAQSkZJRgABAQAA'", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding)", notices
            .get(0).show());

        notices.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-'", "https://origin", notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value (too short: 0)", notices.get(0).show());

        notices.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-abc'", "https://origin", notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value (should be multiple of 4 bytes: 3). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());
    }

    @Test
    public void testIllegalChars() {
        ArrayList<Notice> notices = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-12rwf5tegfszeq23ewv4cgefw43^'", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());

        notices.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-1^=='", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());
    }

    @Test
    public void testIllegalPadding() {
        ArrayList<Notice> notices = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-12=+'", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value padding (illegal characters). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());

        notices.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-1==='", "https://origin",
            notices);
        assertEquals(1, notices.size());
        assertEquals("Invalid base64-value (bad padding). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());
    }

    @Test
    public void testMultipleWarnings() {
        ArrayList<Notice> notices = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-31231asda_dsdsxc'", "https://origin",
            notices);
        assertEquals(2, notices.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", notices
            .get(0).show());
        assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding)", notices
            .get(1).show());

    }
}
