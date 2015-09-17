package com.shapesecurity.salvation;

import org.junit.Test;

import java.util.ArrayList;

import com.shapesecurity.salvation.Parser.ParseException;
import com.shapesecurity.salvation.Tokeniser.TokeniserException;
import com.shapesecurity.salvation.data.Warning;

import static org.junit.Assert.*;

public class Base64ValueTest {

    @Test
    public void testIllegalDecodedSize() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding)", warnings.get(0).show());

        warnings.clear();
        Parser.parse("script-src 'self' 'sha256-K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols=' https://example.com", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());
    }

    @Test
    public void testIllegalLength() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-/9j/4AAQSkZJRgABAQAA'", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding)", warnings.get(0).show());

        warnings.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-'", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value (too short: 0)", warnings.get(0).show());

        warnings.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-abc'", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value (should be multiple of 4 bytes: 3). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());
    }

    @Test
    public void testIllegalChars() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-12rwf5tegfszeq23ewv4cgefw43^'", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());

        warnings.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-1^=='", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());
    }

    @Test
    public void testIllegalPadding() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-12=+'", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value padding (illegal characters). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());

        warnings.clear();
        Parser.parse("script-src 'self' https://example.com 'nonce-1==='", "https://origin", warnings);
        assertEquals(1, warnings.size());
        assertEquals("Invalid base64-value (bad padding). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());
    }

    @Test
    public void testMultipleWarnings() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();

        Parser.parse("script-src 'self' https://example.com 'nonce-31231asda_dsdsxc'", "https://origin", warnings);
        assertEquals(2, warnings.size());
        assertEquals("Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation", warnings.get(0).show());
        assertEquals("CSP specification recommends nonce-value to be at least 128 bits long (before encoding)", warnings.get(1).show());

    }
}
