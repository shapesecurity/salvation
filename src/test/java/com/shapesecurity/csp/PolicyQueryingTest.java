package com.shapesecurity.csp;

import com.shapesecurity.csp.Parser.ParseException;
import com.shapesecurity.csp.Tokeniser.TokeniserException;
import com.shapesecurity.csp.data.Base64Value;
import com.shapesecurity.csp.data.Policy;
import com.shapesecurity.csp.data.URI;
import com.shapesecurity.csp.directiveValues.HashSource;
import com.shapesecurity.csp.directiveValues.MediaType;
import com.shapesecurity.csp.directives.*;
import org.junit.Test;

import static org.junit.Assert.*;

public class PolicyQueryingTest extends CSPTest {

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testGetDirectiveByType() throws ParseException, TokeniserException {
        assertEquals("child-src", parse("child-src").getDirectiveByType(ChildSrcDirective.class).show());
        assertEquals("connect-src", parse("connect-src") .getDirectiveByType(ConnectSrcDirective.class).show());
        assertEquals("default-src", parse("default-src").getDirectiveByType(DefaultSrcDirective.class).show());
        assertEquals("font-src", parse("font-src").getDirectiveByType(FontSrcDirective.class).show());
        assertEquals("img-src", parse("img-src").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("media-src", parse("media-src").getDirectiveByType(MediaSrcDirective.class).show());
        assertEquals("object-src", parse("object-src").getDirectiveByType(ObjectSrcDirective.class).show());
        assertEquals("script-src", parse("script-src").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("style-src", parse("style-src").getDirectiveByType(StyleSrcDirective.class).show());
    }

    @Test
    public void testDirectiveContains() throws ParseException, TokeniserException {
        Policy p = parse("script-src a b c");
        Policy q = parse("script-src a");
        Policy r = parse("script-src m");
        Policy s = parse("report-uri /z");
        ScriptSrcDirective d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
        assertNotNull(d1);
        assertNotNull(d2);
        DirectiveValue value = d2.values().iterator().next();
        assertTrue("directive contains", d1.contains(value));
        ScriptSrcDirective d3 = r.getDirectiveByType(ScriptSrcDirective.class);
        assertNotNull(d3);
        value = d3.values().iterator().next();
        assertFalse("directive doesn't contain", d1.contains(value));
        ReportUriDirective d4 = s.getDirectiveByType(ReportUriDirective.class);
        assertNotNull(d4);
        assertEquals("report-uri http://example.com/z", d4.show());
        value = d3.values().iterator().next();
        assertFalse("directive doesn't contain", d1.contains(value));
    }

    @Test
    public void testAllowsFromSource() throws ParseException, TokeniserException {
        Policy p;

        p = Parser.parse("default-src 'none'; img-src https: 'self' http://abc.am/; style-src https://*.abc.am:*; script-src 'self' https://abc.am", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://a.com/12")));
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://abc.am")));
        assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parse("https://abc.am")));
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://abc.com/12")));
        assertFalse("resource is not allowed", p.allowsImgFromSource(URI.parse("http://a.com/12")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));
        assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));

        p = Parser.parse("default-src 'none'", "https://abc.com");
        assertFalse("resource is not allowed", p.allowsImgFromSource(URI.parse("https://abc.am")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));
        assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));

        p = Parser.parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://abc.am")));
        assertTrue("resource is allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));
        assertTrue("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));
    }

    @Test
    public void testAllowsUnsafeInline() throws ParseException, TokeniserException {
        Policy p;

        p = Parser.parse("script-src https: 'self' http://a", URI.parse("https://abc.com"));
        assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
        assertFalse("inline style is not allowed", p.allowsUnsafeInlineStyle());
        p = Parser.parse("script-src https: 'self' http://a 'unsafe-inline'", URI.parse("https://abc.com"));
        assertTrue("inline script is allowed", p.allowsUnsafeInlineScript());
        assertFalse("inline style is not allowed", p.allowsUnsafeInlineStyle());

        p = Parser.parse("style-src https: 'self' http://a", URI.parse("https://abc.com"));
        assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
        assertFalse("inline style is not allowed", p.allowsUnsafeInlineStyle());
        p = Parser.parse("style-src https: 'self' http://a 'unsafe-inline'", URI.parse("https://abc.com"));
        assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
        assertTrue("inline style is allowed", p.allowsUnsafeInlineStyle());

        p = Parser.parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
        assertTrue("inline script is allowed", p.allowsUnsafeInlineScript());
        assertTrue("inline style is allowed", p.allowsUnsafeInlineStyle());
        assertTrue("script hash is allowed", p.allowsScriptWithHash(
            HashSource.HashAlgorithm.SHA512,
            new Base64Value("vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertTrue("style hash is allowed",
            p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

    }

    @Test
    public void testAllowsPlugin() throws ParseException, TokeniserException {
        Policy p;

        assertTrue("plugin is allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("a", "b")));
        assertTrue("plugin is allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("a", "b")));
        assertFalse("plugin is not allowed", parse("default-src 'none'").allowsPlugin(new MediaType("z", "b")));
        assertFalse("plugin is not allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("z", "b")));
        assertFalse("plugin is not allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("a", "d")));
        assertFalse("plugin is not allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("", "b")));
    }

    @Test
    public void testAllowsHash() throws ParseException, TokeniserException {
        Policy p;

        p = parse("script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertTrue("script hash is allowed",
            p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("script hash is not allowed",
            p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        p = parse("style-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertTrue("style hash is allowed",
            p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("style hash is not allowed",
            p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        p = Parser.parse("default-src 'none'", "https://abc.com");
        assertFalse("script hash is not allowed",
            p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("style hash is not allowed",
            p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
    }

    @Test
    public void testAllowsNonce() throws ParseException, TokeniserException {
        Policy p;

        p = parse("script-src 'nonce-0gQAAA=='");
        assertTrue("script nonce is allowed", p.allowsScriptWithNonce(new Base64Value("0gQAAA==")));
        assertFalse("script nonce is not allowed", p.allowsScriptWithNonce(new Base64Value("cGl6ZGE=")));

        p = parse("style-src 'nonce-0gQAAA=='");
        assertTrue("style nonce is allowed", p.allowsStyleWithNonce(new Base64Value("0gQAAA==")));
        assertFalse("style nonce is not allowed", p.allowsStyleWithNonce(new Base64Value("cGl6ZGE=")));

        p = Parser.parse("default-src 'none'", "https://abc.com");
        assertFalse("script nonce is not allowed", p.allowsScriptWithNonce(new Base64Value("0gQAAA==")));
        assertFalse("style nonce is not allowed", p.allowsStyleWithNonce(new Base64Value("0gQAAA==")));
    }

    @Test
    public void testAllowsConnect() throws ParseException, TokeniserException {
        Policy p;

        p = Parser.parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("https://abc.com")));
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("http://good.com/")));
        assertFalse("connect is not allowed", p.allowsConnectTo(URI.parse("https://good.com/")));
        assertFalse("connect is not allowed", p.allowsConnectTo(URI.parse("http://aaa.good.com/")));
    }

}
