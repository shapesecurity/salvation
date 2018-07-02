package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.HostSource;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtilsTest extends CSPTest {

	@Test
	public void testURIandOrigins() {
		URI u1 = URI.parse("http://a/123");
		URI u2 = URI.parse("http://a:80/");
		u1 = URI.parseWithOrigin(URI.parse("https://www"), "/34");
		assertEquals("abs uri", "https://www/34", u1.show());
		u1 = URI.parse("http://a:80");
		u2 = URI.parse("http://a");
		assertTrue("URIs are equal", u1.equals(u2));
	}

	@Test
	public void testSplitBySpec() {
		assertEquals("[]", HostSource.splitBySpec("", '/').toString());
		assertEquals("[, ]", HostSource.splitBySpec("/", '/').toString());
		assertEquals("[a, ]", HostSource.splitBySpec("a/", '/').toString());
		assertEquals("[, a]", HostSource.splitBySpec("/a", '/').toString());
		assertEquals("[, a, ]", HostSource.splitBySpec("/a/", '/').toString());
		assertEquals("[, a, b]", HostSource.splitBySpec("/a/b", '/').toString());
		assertEquals("[, a, b, ]", HostSource.splitBySpec("/a/b/", '/').toString());
	}

	@Test
	public void testHostMatch() {
		assertTrue(HostSource.hostMatches("*.example.com", "a.example.com"));
		assertTrue(HostSource.hostMatches("*.example.com", "A.example.com"));
		assertTrue(HostSource.hostMatches("*.example.com", "A.EXAMPLE.COM"));
		assertTrue(HostSource.hostMatches("*.EXAMPLE.COM", "a.EXAMPLE.com"));
		assertTrue(HostSource.hostMatches("*.example.com", "a.b.example.com"));
		assertFalse(HostSource.hostMatches("*.example.com", "example.com"));
		assertFalse(HostSource.hostMatches("*.example.com", "example.com.org"));

		assertFalse(HostSource.hostMatches("example.com", "a.example.com"));
		assertFalse(HostSource.hostMatches("example.com", "a.b.example.com"));
		assertTrue(HostSource.hostMatches("example.com", "example.com"));
		assertTrue(HostSource.hostMatches("EXAMPLE.COM", "example.com"));
		assertFalse(HostSource.hostMatches("example.com", "example.com.org"));

		assertTrue(HostSource.hostMatches("127.0.0.1", "127.0.0.1"));
		assertFalse(HostSource.hostMatches("127.0.0.2", "127.0.0.2"));
		assertFalse(HostSource.hostMatches("127.0.0.1.1", "127.0.1.1"));
		assertFalse(HostSource.hostMatches("1.127.0.0.1.1", "1.127.0.1.1"));
		assertFalse(HostSource.hostMatches("192.168.1.1", "192.168.1.1"));


		assertFalse(HostSource.hostMatches("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1"));
		assertFalse(HostSource.hostMatches("::1", "::1"));
		assertFalse(HostSource.hostMatches("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
		assertFalse(HostSource.hostMatches("2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"));
		assertFalse(HostSource.hostMatches("[2001:db8:85a3:8d3:1319:8a2e:370:7348]", "[2001:db8:85a3:8d3:1319:8a2e:370:7348]"));
		assertFalse(HostSource.hostMatches("fe80::9a01:a7ff:fe8f:3c5d", "fe80::9a01:a7ff:fe8f:3c5d"));

	}
}
