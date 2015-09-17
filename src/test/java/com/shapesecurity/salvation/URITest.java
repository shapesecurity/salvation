package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.URI;
import org.junit.Test;

import static org.junit.Assert.*;

public class URITest extends CSPTest {

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
}
