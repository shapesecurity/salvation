package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Base64Value;
import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.HashSource;
import com.shapesecurity.salvation.directiveValues.MediaType;
import com.shapesecurity.salvation.directives.*;
import org.junit.Test;

import static org.junit.Assert.*;

public class PolicyQueryingTest extends CSPTest {

    @Test @SuppressWarnings("ConstantConditions") public void testGetDirectiveByType() {
        assertEquals("child-src", parse("child-src").getDirectiveByType(ChildSrcDirective.class).show());
        assertEquals("connect-src", parse("connect-src").getDirectiveByType(ConnectSrcDirective.class).show());
        assertEquals("default-src", parse("default-src").getDirectiveByType(DefaultSrcDirective.class).show());
        assertEquals("font-src", parse("font-src").getDirectiveByType(FontSrcDirective.class).show());
        assertEquals("img-src", parse("img-src").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("media-src", parse("media-src").getDirectiveByType(MediaSrcDirective.class).show());
        assertEquals("object-src", parse("object-src").getDirectiveByType(ObjectSrcDirective.class).show());
        assertEquals("script-src", parse("script-src").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("style-src", parse("style-src").getDirectiveByType(StyleSrcDirective.class).show());
    }

    @Test public void testDirectiveContains() {
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

    @Test public void testDirectiveContainsCaseSensitivity() {
        Policy p = parse("script-src a b c");
        Policy q = parse("script-src A");
        Policy r = parse("script-src M");
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
    }

    @Test public void testAllowsFromSource() {
        Policy p;

        p = Parser.parse(
            "default-src 'none'; img-src https: 'self' http://abc.am/; style-src https://*.abc.am:*; script-src 'self' https://abc.am https://*.cde.am/a",
            URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://a.com/12")));
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://abc.am")));
        assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parse("https://abc.am")));
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("https://abc.com/12")));
        assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parse("httpS://www.cDE.am/a")));
        assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parse("https://www.cde.am/a")));
        assertFalse("resource is not allowed", p.allowsImgFromSource(URI.parse("http://a.com/12")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));
        assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.cde.am/A")));
        assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));

        p = Parser.parse("default-src 'none'", "https://abc.com");
        assertFalse("resource is not allowed", p.allowsImgFromSource(URI.parse("https://abc.am")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));
        assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("https://www.def.am:555")));


        p = Parser.parse("default-src *:*", "http://abc.com");
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("http://abc.am")));
        assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));

        p = Parser.parse("default-src 'none'; frame-src http:;", URI.parse("https://abc.com"));
        assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));

        p = Parser.parse("child-src http:;", URI.parse("https://abc.com"));
        assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));

        p = Parser.parse("frame-src https:; child-src http:;", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));
    }

    @Test public void testAllowsUnsafeInline() {
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
        assertTrue("script hash is allowed", p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
            "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertTrue("style hash is allowed",
            p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

    }

    @Test public void testAllowsPlugin() {
        assertTrue("plugin is allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("A", "b")));
        assertTrue("plugin is allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("a", "B")));
        assertTrue("plugin is allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("A", "B")));
        assertTrue("plugin is allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("a", "b")));
        assertFalse("plugin is not allowed", parse("default-src 'none'").allowsPlugin(new MediaType("z", "b")));
        assertFalse("plugin is not allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("z", "b")));
        assertFalse("plugin is not allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("a", "d")));
        assertFalse("plugin is not allowed", parse("plugin-types a/b c/d").allowsPlugin(new MediaType("", "b")));
    }

    @Test public void testAllowsHash() {
        Policy p;

        p = parse(
            "script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertTrue("script hash is allowed", p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
            "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("script hash is not allowed",
            p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        p = parse(
            "style-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertTrue("style hash is allowed", p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
            "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("style hash is not allowed",
            p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        p = Parser.parse("default-src 'none'", "https://abc.com");
        assertFalse("script hash is not allowed", p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512,
            new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("style hash is not allowed", p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
            "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
    }

    @Test public void testAllowsNonce() {
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

    @Test public void testAllowsConnect() {
        Policy p;

        p = Parser.parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("https://abc.com")));
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("http://good.com/")));
        assertFalse("connect is not allowed", p.allowsConnectTo(URI.parse("https://good.com/")));
        assertFalse("connect is not allowed", p.allowsConnectTo(URI.parse("http://aaa.good.com/")));
        assertFalse("connect is not allowed", p.allowsConnectTo(URI.parse("wss://abc.com/")));
        assertFalse("connect is not allowed", p.allowsConnectTo(URI.parse("http://abc.com/")));
    }

    @Test public void testAllowsFrameAncestor() {
        Policy p;

        p = Parser.parse("", "https://abc.com");
        assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parse("https://abc.com")));
        assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parse("ftp://cde.com")));

        p = Parser.parse("frame-ancestors 'none'", "https://abc.com");
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("ftp://cde.com")));
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("https://abc.com")));

        p = Parser.parse("frame-ancestors 'self'", "https://abc.com");
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("ftp://cde.com")));
        assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parse("https://abc.com")));

        p = Parser.parse("frame-ancestors https:", "https://abc.com");
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("ftp://cde.com")));
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("http://cde.com")));
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("http://abc.com")));
        assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parse("https://abc.com")));

        p = Parser.parse("frame-ancestors http://example.com https:", "https://abc.com");
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("ftp://cde.com")));
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("http://cde.com")));
        assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parse("http://abc.com")));
        assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parse("https://example.com")));
        assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parse("http://example.com")));
    }

    @Test public void testPaths() {
        Policy p;

        p = Parser.parse("script-src example.com/a", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/A")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/c")));

        p = Parser.parse("script-src example.com/a/", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/A/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/c")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/A/b/c")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/B/C")));

        p = Parser.parse("script-src example.com/a/b", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/B")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/c")));

        p = Parser.parse("script-src example.com/a/b/", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/c")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/C")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/A/B/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/A/B/c")));

        p = Parser.parse("script-src example.com/a/b/c", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/A/B/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/c")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b/C")));
    }

    @Test public void testLocalSchemes() {
        Policy p = Parser.parse("script-src *.example.com data: blob:; frame-ancestors data: about:", "http://example.com");
        assertTrue(p.allowsScriptFromSource(new GUID("data:")));
        assertTrue(p.allowsScriptFromSource(new GUID("DATA:")));
        assertTrue(p.allowsScriptFromSource(new GUID("blob:")));
        assertTrue(p.allowsScriptFromSource(new GUID("BLOB:")));
        assertFalse(p.allowsScriptFromSource(new GUID("about::")));
        assertFalse(p.allowsScriptFromSource(new GUID("ABOUT:")));
        assertTrue(p.allowsFrameAncestor(new GUID("data:")));
        assertTrue(p.allowsFrameAncestor(new GUID("DATA:")));
        assertTrue(p.allowsFrameAncestor(new GUID("about:")));
        assertTrue(p.allowsFrameAncestor(new GUID("ABOUT:")));
        assertFalse(p.allowsFrameAncestor(new GUID("blob:")));
        assertFalse(p.allowsFrameAncestor(new GUID("BLOB:")));
        assertFalse(p.allowsFrameAncestor(new GUID("custom.scheme:")));

        p = Parser.parse("script-src *.example.com DATA: BLOB:; frame-ancestors DATA: ABOUT:", "http://example.com");
        assertTrue(p.allowsScriptFromSource(new GUID("data:")));
        assertTrue(p.allowsScriptFromSource(new GUID("DATA:")));
        assertTrue(p.allowsScriptFromSource(new GUID("blob:")));
        assertTrue(p.allowsScriptFromSource(new GUID("BLOB:")));
        assertFalse(p.allowsScriptFromSource(new GUID("about::")));
        assertFalse(p.allowsScriptFromSource(new GUID("ABOUT:")));
        assertTrue(p.allowsFrameAncestor(new GUID("data:")));
        assertTrue(p.allowsFrameAncestor(new GUID("DATA:")));
        assertTrue(p.allowsFrameAncestor(new GUID("about:")));
        assertTrue(p.allowsFrameAncestor(new GUID("ABOUT:")));
        assertFalse(p.allowsFrameAncestor(new GUID("blob:")));
        assertFalse(p.allowsFrameAncestor(new GUID("BLOB:")));
        assertFalse(p.allowsFrameAncestor(new GUID("custom.scheme:")));

        p = Parser.parse("script-src *.example.com custom-scheme:; frame-ancestors custom.scheme2:", "http://example.com");
        assertFalse(p.allowsScriptFromSource(new GUID("custom.scheme:")));
        assertTrue(p.allowsScriptFromSource(new GUID("custom-scheme:")));
        assertFalse(p.allowsFrameAncestor(new GUID("BLOB:")));
        assertFalse(p.allowsFrameAncestor(new GUID("custom-scheme:")));
        assertTrue(p.allowsFrameAncestor(new GUID("custom.scheme2:")));


    }

    @Test public void testWildcards() {
        Policy p;

        p = Parser.parse("script-src *", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsScriptFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/PATH")));
        assertTrue(p.allowsScriptFromSource(URI.parse("ws://example.com/PATH")));
        assertTrue(p.allowsScriptFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(new GUID("data:")));
        assertFalse(p.allowsScriptFromSource(new GUID("custom.scheme:")));


        p = Parser.parse("script-src http://*", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsScriptFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(new GUID("data:")));
        assertFalse(p.allowsScriptFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("style-src *:80", "http://example.com");
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(new GUID("data:")));
        assertFalse(p.allowsStyleFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("style-src *:80", "https://example.com");
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(new GUID("data:")));
        assertFalse(p.allowsStyleFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("style-src *:80", "ftp://example.com");
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(new GUID("data:")));
        assertFalse(p.allowsStyleFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("img-src ftp://*", "http://example.com");
        assertFalse(p.allowsImgFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsImgFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsImgFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsImgFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsImgFromSource(URI.parse("ftp://example.com:80")));
        assertFalse(p.allowsImgFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsImgFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsImgFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsImgFromSource(new GUID("data:")));
        assertFalse(p.allowsImgFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("style-src *:*", "http://example.com");
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(new GUID("data:")));
        assertFalse(p.allowsStyleFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("style-src http://*:*", "http://example.com");
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(new GUID("data:")));
        assertFalse(p.allowsStyleFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("style-src ftp://*:*", "http://example.com");
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsStyleFromSource(new GUID("data:")));
        assertFalse(p.allowsStyleFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("img-src */path", "http://example.com");
        assertFalse(p.allowsImgFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsImgFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsImgFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsImgFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsImgFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsImgFromSource(URI.parse("http://example.com/path")));
        assertFalse(p.allowsImgFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsImgFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsImgFromSource(new GUID("data:")));
        assertFalse(p.allowsImgFromSource(new GUID("custom.scheme:")));

        p = Parser.parse("script-src *.example.com", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.b.example.com/c/d")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.b.example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://www.example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(new GUID("data:")));
        assertFalse(p.allowsScriptFromSource(new GUID("custom.scheme:")));
    }

    @Test public void testHasSomeEffect() {
        Policy p = Parser.parse("", "http://example.com");
        assertFalse(p.hasSomeEffect());
        p = Parser.parse("script-src a; upgrade-insecure-requests; report-to a", "http://example.com");
        assertTrue(p.hasSomeEffect());
        p = Parser.parse("report-to a", "http://example.com");
        assertFalse(p.hasSomeEffect());
    }
}
