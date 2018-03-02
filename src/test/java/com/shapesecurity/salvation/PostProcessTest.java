package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Policy;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PostProcessTest extends CSPTest {

    @Test public void testKeywordReduce() {
        Policy p;
        p = parse("script-src 'unsafe-inline'; style-src 'unsafe-inline';");
        p.postProcessOptimisation();
        assertEquals("default-src 'unsafe-inline'", p.show());

        p = parse("script-src 'unsafe-eval'; style-src 'unsafe-eval';");
        p.postProcessOptimisation();
        assertEquals("default-src 'unsafe-eval'", p.show());

        p = parse("script-src 'unsafe-eval' 'nonce-123'; style-src 'unsafe-eval' 'nonce-123';");
        p.postProcessOptimisation();
        assertEquals("default-src 'unsafe-eval' 'nonce-123'", p.show());

        p = parse("script-src 'unsafe-eval' 'nonce-123'; style-src 'unsafe-eval';");
        p.postProcessOptimisation();
        assertEquals("script-src 'unsafe-eval' 'nonce-123'; style-src 'unsafe-eval'", p.show());

        p = parse("script-src 'self'; style-src 'self';");
        p.postProcessOptimisation();
        assertEquals("default-src 'self'", p.show());

        p = parse("script-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'; style-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'");
        p.postProcessOptimisation();
        assertEquals("default-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'", p.show());

        p = parse("script-src 'nonce-1234'; style-src 'nonce-1234'; default-src a");
        p.postProcessOptimisation();
        assertEquals("script-src 'nonce-1234'; style-src 'nonce-1234'; default-src a", p.show());
    }

    @Test public void testFetchDirectiveReduce() {
        Policy p = parse("script-src a; style-src a; img-src a; child-src a; connect-src a; font-src a; media-src a; object-src a; manifest-src a; prefetch-src a ");
        p.postProcessOptimisation();
        assertEquals("default-src a", p.show());

        p = parse("form-action a; script-src a; style-src a; img-src a; child-src a; connect-src a; font-src a; media-src a; object-src a; manifest-src a; prefetch-src a ");
        p.postProcessOptimisation();
        assertEquals("form-action a; default-src a", p.show());

        p = parse("script-src a; style-src a; img-src a; child-src a; connect-src a; base-uri a; font-src a; media-src a; object-src a; manifest-src a; prefetch-src a ");
        p.postProcessOptimisation();
        assertEquals("base-uri a; default-src a", p.show());
    }

}
