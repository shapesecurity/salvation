package com.shapesecurity.salvation;

import java.util.Collections;
import java.util.stream.Stream;

import com.shapesecurity.salvation.data.Base64Value;
import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.HashSource;
import com.shapesecurity.salvation.directiveValues.HostSource;
import com.shapesecurity.salvation.directiveValues.KeywordSource;
import com.shapesecurity.salvation.directiveValues.MediaType;
import com.shapesecurity.salvation.directiveValues.NonceSource;
import com.shapesecurity.salvation.directiveValues.SourceExpression;
import com.shapesecurity.salvation.directives.ChildSrcDirective;
import com.shapesecurity.salvation.directives.ConnectSrcDirective;
import com.shapesecurity.salvation.directives.DefaultSrcDirective;
import com.shapesecurity.salvation.directives.DirectiveValue;
import com.shapesecurity.salvation.directives.FontSrcDirective;
import com.shapesecurity.salvation.directives.FrameSrcDirective;
import com.shapesecurity.salvation.directives.ImgSrcDirective;
import com.shapesecurity.salvation.directives.MediaSrcDirective;
import com.shapesecurity.salvation.directives.ObjectSrcDirective;
import com.shapesecurity.salvation.directives.ReportUriDirective;
import com.shapesecurity.salvation.directives.ScriptSrcDirective;
import com.shapesecurity.salvation.directives.StyleSrcDirective;
import com.shapesecurity.salvation.directives.WorkerSrcDirective;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
        assertEquals("frame-src", parse("frame-src").getDirectiveByType(FrameSrcDirective.class).show());
        assertEquals("worker-src", parse("worker-src").getDirectiveByType(WorkerSrcDirective.class).show());
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
        assertFalse("resource is not allowed", p.allowsWorkerFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("https://www.def.am:555")));


        p = Parser.parse("default-src *:*", "http://abc.com");
        assertTrue("resource is allowed", p.allowsImgFromSource(URI.parse("http://abc.am")));
        assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));

        p = Parser.parse("default-src 'none'; frame-src http:;", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));

        p = Parser.parse("default-src 'none'; worker-src http:;", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsWorkerFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsWorkerFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));

        p = Parser.parse("child-src http:;", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("http://www.def.am:555")));
        assertTrue("resource is not allowed", p.allowsChildFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));

        p = Parser.parse("frame-src https:; child-src http:;", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parse("https://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parse("http://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsChildFromSource(URI.parse("https://www.def.am:555")));
        assertTrue("resource is allowed", p.allowsChildFromSource(URI.parse("http://www.def.am:555")));
        
        p = Parser.parse("font-src https://font.com http://font.org", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsFontFromSource(URI.parse("https://font.com")));
        assertFalse("resource is not allowed", p.allowsFontFromSource(URI.parse("https://font.com:555")));
        assertFalse("resource is not allowed", p.allowsFontFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsFontFromSource(URI.parse("https://someco.net")));
        
        p = Parser.parse("object-src https://object.com http://object.org", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsObjectFromSource(URI.parse("https://object.com")));
        assertFalse("resource is not allowed", p.allowsObjectFromSource(URI.parse("https://object.com:555")));
        assertFalse("resource is not allowed", p.allowsObjectFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsObjectFromSource(URI.parse("https://someco.net")));
        
        p = Parser.parse("media-src https://media.com http://media.org", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsMediaFromSource(URI.parse("https://media.com")));
        assertFalse("resource is not allowed", p.allowsMediaFromSource(URI.parse("https://media.com:555")));
        assertFalse("resource is not allowed", p.allowsMediaFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsMediaFromSource(URI.parse("https://someco.net")));
        
        p = Parser.parse("manifest-src https://manifest.com http://manifest.org", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsManifestFromSource(URI.parse("https://manifest.com")));
        assertFalse("resource is not allowed", p.allowsManifestFromSource(URI.parse("https://manifest.com:555")));
        assertFalse("resource is not allowed", p.allowsManifestFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsManifestFromSource(URI.parse("https://someco.net")));

        p = Parser.parse("prefetch-src https://prefetchy.com http://prefetchy.org", URI.parse("https://abc.com"));
        assertTrue("resource is allowed", p.allowsPrefetchFromSource(URI.parse("https://prefetchy.com")));
        assertFalse("resource is not allowed", p.allowsPrefetchFromSource(URI.parse("https://prefetchy.com:555")));
        assertFalse("resource is not allowed", p.allowsPrefetchFromSource(URI.parse("http://www.def.am:555")));
        assertFalse("resource is not allowed", p.allowsPrefetchFromSource(URI.parse("https://someco.net")));
        
    }

    @Test public void testSecureSchemes() {
        Policy p;

        p = Parser.parse("script-src http:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src http:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("ws://a")));

        p = Parser.parse("script-src http:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("wss://a")));

        p = Parser.parse("script-src http:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src http:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("ftp://a")));

        p = Parser.parse("script-src http:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("sftp://a")));

        p = Parser.parse("script-src ws:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src ws:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("ws://a")));

        p = Parser.parse("script-src ws:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("wss://a")));

        p = Parser.parse("script-src ws:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src ws:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("ftp://a")));

        p = Parser.parse("script-src ws:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("sftp://a")));

        p = Parser.parse("script-src wss:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src wss:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("ws://a")));

        p = Parser.parse("script-src wss:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("wss://a")));

        p = Parser.parse("script-src wss:;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src wss:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("ftp://a")));

        p = Parser.parse("script-src wss:;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("sftp://a")));

        p = Parser.parse("script-src a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src https://a;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src http://a;", "https://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src http://a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src http://a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src https://a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src ws://a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src wss://a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));

        p = Parser.parse("script-src wss://a;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("ws://a")));

        p = Parser.parse("script-src wss://a;", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a")));

        p = Parser.parse("script-src ws://a;", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("https://a")));
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

        p = Parser.parse("default-src * 'unsafe-inline' 'nonce-123'", "https://abc.com");
        assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
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

        p = Parser.parse("default-src * 'unsafe-inline' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", "https://abc.com");
        assertTrue("script hash is allowed", p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
            "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("unknown script is not allowed", p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA256, new Base64Value(
            "7HY1KLziIDGNSsu67SifYO1B69r1EFEfvPg3McqyIcM=")));
        assertFalse("unknown script is not allowed", p.allowsUnsafeInlineScript());
        assertFalse("unknown style is not allowed", p.allowsUnsafeInlineStyle());
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

        p = Parser.parse("default-src * 'unsafe-inline' 'nonce-0gQAAA=='", "https://abc.com");
        assertTrue("script nonce is allowed", p.allowsScriptWithNonce(new Base64Value("0gQAAA==")));
        assertFalse("script wrong nonce is not allowed", p.allowsScriptWithNonce(new Base64Value("1234")));
        assertFalse("unsafe inline script is not allowed", p.allowsUnsafeInlineScript());
        assertFalse("unsafe inline style is not allowed", p.allowsUnsafeInlineStyle());
    }

    @Test public void testAllowsAttributeWithHash() {
        Policy p;

        p = parse(
                "script-src 'unsafe-hashed-attributes' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertTrue("attribute with hash is allowed", p.allowsAttributeWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("script hash is not allowed",
                p.allowsAttributeWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        p = parse(
                "script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertFalse("attribute with hash is not allowed", p.allowsAttributeWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));

        p = parse(
                "default-src 'unsafe-hashed-attributes' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertTrue("attribute with hash is allowed", p.allowsAttributeWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse("script hash is not allowed",
                p.allowsAttributeWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));
        
        p = parse(
                "default-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertFalse("attribute with hash is not allowed", p.allowsAttributeWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
    }

    @Test public void testAllowsConnect() {
        Policy p;

        p = Parser.parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("https://abc.com")));
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("http://good.com/")));
        assertTrue("connect is allowed", p.allowsConnectTo(URI.parse("https://good.com/")));
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

    @Test public void testHosts() {
        Policy p;

        p = Parser.parse("script-src http://*.example.com/a", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://A.example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.EXAMPLE.COM/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.b.example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com.org/a")));

        p = Parser.parse("script-src http://*.EXAMPLE.COM/a", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://A.example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.EXAMPLE.COM/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://a.b.example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com.org/a")));

        p = Parser.parse("script-src http://example.com/a", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://EXAMPLE.COM/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a.example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://A.example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a.EXAMPLE.COM/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com.org/a")));

        p = Parser.parse("script-src http://EXAMPLE.COM/a", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://EXAMPLE.COM/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a.example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://A.example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://a.EXAMPLE.COM/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com.org/a")));

        p = Parser.parse("script-src http://127.0.0.1/a", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://127.0.0.1/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://127.0.0.1.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://127.0.0.2/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://127.0.0.1.1/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://10.10.0.1/a")));

        p = Parser.parse("script-src http://192.168.1.1/a", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://192.168.1.1/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://192.168.0.1/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://127.0.0.1/a")));

        // TODO: we can't parse below URLs now
//        p = Parser.parse("script-src http://0:0:0:0:0:0:0:1/a", "http://example.com");
//        assertFalse(p.allowsScriptFromSource(URI.parse("http://0:0:0:0:0:0:0:1/a")));

//        p = Parser.parse("script-src http://::1/a", "http://example.com");
//        assertFalse(p.allowsScriptFromSource(URI.parse("http://::1/a")));

//        p = Parser.parse("script-src http://2001:db8:85a3:8d3:1319:8a2e:370:7348/a", "http://example.com");
//        assertFalse(p.allowsScriptFromSource(URI.parse("http://2001:db8:85a3:8d3:1319:8a2e:370:7348/a")));

//        p = Parser.parse("script-src http://[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443/a", "http://example.com");
//        assertFalse(p.allowsScriptFromSource(URI.parse("http://[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443/a")));
    }

    @Test public void testPaths() {
        Policy p;

        p = Parser.parse("script-src example.com/a", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com////a")));

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

        p = Parser.parse("script-src example.com/a/b%3Bzzz%2Cqqq", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/a/b%3Bzzz")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b%3Bzzz%2Cqqq")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/a/b;zzz,qqq")));

        p = Parser.parse("script-src example.com/%21/%24/%26/%27/%28/%29/%2A/%2C/%3A/%3B", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/!/$/&/'/(/)/*/,/:/;")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%21/%24/%26/%27/%28/%29/%2A/%2C/%3A/%3B")));

        // TODO: this is valid in Chrome
//        p = Parser.parse("script-src example.com/%GG", "http://example.com");
//        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%GG")));
//      // TODO: this is valid in Chrome
//        p = Parser.parse("script-src example.com/%%GGpath", "http://example.com");
//        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%GG")));

        // TODO: we should throw on this, as it isn't valid UTF-8 percent encoding
//        p = Parser.parse("script-src example.com/%ef", "http://example.com");

        p = Parser.parse("script-src example.com/%C3%AF/", "http://example.com");
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com/%EF/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%C3%AF/")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%C3%AF/%65")));
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

    @Test public void testStrictDynamic() {
        Policy p;

        p = Parser.parse("default-src 'unsafe-inline' 'strict-dynamic'", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertTrue(p.allowsUnsafeInlineStyle());
        assertFalse(p.allowsScriptWithNonce("123"));
        assertTrue(p.allowsStyleWithNonce("123"));
        assertFalse(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertTrue(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));

        p = Parser.parse("default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertTrue(p.allowsScriptWithNonce("123"));
        assertFalse(p.allowsScriptWithNonce("345"));
        assertTrue(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        assertFalse(p.allowsUnsafeInlineStyle());
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.allowsStyleWithNonce("123"));
        assertFalse(p.allowsStyleWithNonce("345"));
        assertTrue(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));

        p = Parser.parse("default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='; script-src;", "http://example.com");
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertFalse(p.allowsUnsafeInlineStyle());

        assertFalse(p.allowsScriptWithNonce("123"));
        assertFalse(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));

        assertTrue(p.allowsStyleWithNonce("123"));
        assertTrue(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "cGl6ZGE=")));

        p = Parser.parse("default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='; style-src;", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineStyle());

        assertTrue(p.allowsScriptWithNonce("123"));
        assertFalse(p.allowsScriptWithNonce("345"));
        assertTrue(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));

        assertFalse(p.allowsStyleWithNonce("123"));
        assertFalse(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));

        p = Parser.parse("script-src 'unsafe-inline' 'nonce-forscript' 'strict-dynamic'; style-src 'unsafe-inline' 'nonce-forstyle'", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertFalse(p.allowsUnsafeInlineStyle());
        assertFalse(p.allowsScriptWithNonce("123"));
        assertFalse(p.allowsStyleWithNonce("123"));
        assertFalse(p.allowsScriptWithNonce("1234"));
        assertFalse(p.allowsStyleWithNonce("1234"));
        assertFalse(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));
        assertFalse(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));
        assertTrue(p.allowsScriptWithNonce("forscript"));
        assertFalse(p.allowsStyleWithNonce("forscript"));
        assertFalse(p.allowsScriptWithNonce("forstyle"));
        assertTrue(p.allowsStyleWithNonce("forstyle"));
    }

    @Test public void testHashAndNonceInvalidateUnsafeInline() {
        Policy p;

        p = Parser.parse("default-src 'unsafe-inline' 'nonce-123' ", "http://example.com");
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof HashSource));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x instanceof HashSource));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(DefaultSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertFalse(p.allowsUnsafeInlineStyle());
        assertTrue(p.allowsScriptWithNonce("123"));
        assertTrue(p.allowsStyleWithNonce("123"));
        assertFalse(p.allowsScriptWithNonce("1234"));
        assertFalse(p.allowsStyleWithNonce("1234"));

        p = Parser.parse("default-src 'unsafe-inline' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==' ", "http://example.com");
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.allowsUnsafeInlineScript());
        assertFalse(p.allowsUnsafeInlineStyle());
        assertFalse(p.allowsScriptWithNonce("123"));
        assertFalse(p.allowsStyleWithNonce("123"));
        assertFalse(p.allowsScriptWithNonce("1234"));
        assertFalse(p.allowsStyleWithNonce("1234"));
        assertTrue(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertTrue(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertFalse(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));
        assertFalse(p.allowsStyleWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value("cGl6ZGE=")));
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

        p = Parser.parse("script-src *", "applewebdata://example.com");
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
        assertTrue(p.allowsScriptFromSource(URI.parse("applewebdata://resource")));
        assertFalse(p.allowsScriptFromSource(URI.parse("somethingelse://resource")));

        p = Parser.parse("script-src *", "file://resource");
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
        assertTrue(p.allowsScriptFromSource(URI.parse("file://anotherresource")));
        assertFalse(p.allowsScriptFromSource(URI.parse("applewebdata://resource")));
        assertFalse(p.allowsScriptFromSource(URI.parse("somethingelse://resource")));

        p = Parser.parse("script-src *", new GUID("data:text/html,%3Ch1%3EHello%2C%20World!%3C%2Fh1%3E"));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsScriptFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/PATH")));
        assertTrue(p.allowsScriptFromSource(URI.parse("ws://example.com/PATH")));
        assertTrue(p.allowsScriptFromSource(URI.parse("wss://example.com/PATH")));
        assertTrue(p.allowsScriptFromSource(new GUID("data:")));
        assertFalse(p.allowsScriptFromSource(URI.parse("somethingelse://resource")));

        p = Parser.parse("script-src http://*", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("https://example.com")));
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
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsStyleFromSource(URI.parse("ftp://example.com:80")));
        assertFalse(p.allowsStyleFromSource(URI.parse("http://example.com/path")));
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
        assertTrue(p.allowsStyleFromSource(URI.parse("https://example.com")));
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
        assertTrue(p.allowsStyleFromSource(URI.parse("https://example.com")));
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
        assertTrue(p.allowsScriptFromSource(URI.parse("http://www.EXAMPLE.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsScriptFromSource(new GUID("data:")));
        assertFalse(p.allowsScriptFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("font-src *", "http://example.com");
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFontFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsFontFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsFontFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com/PATH")));
        assertTrue(p.allowsFontFromSource(URI.parse("ws://example.com/PATH")));
        assertTrue(p.allowsFontFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsFontFromSource(new GUID("data:")));
        assertFalse(p.allowsFontFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("font-src http://*", "http://example.com");
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFontFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsFontFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsFontFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsFontFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://example.com/PATH")));
        assertFalse(p.allowsFontFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsFontFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsFontFromSource(new GUID("data:")));
        assertFalse(p.allowsFontFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("font-src *.example.com", "http://example.com");
        assertTrue(p.allowsFontFromSource(URI.parse("http://a.b.example.com/c/d")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://a.b.example.com")));
        assertTrue(p.allowsFontFromSource(URI.parse("http://www.example.com")));
        assertFalse(p.allowsFontFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsFontFromSource(URI.parse("http://com")));
        assertFalse(p.allowsFontFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsFontFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsFontFromSource(new GUID("data:")));
        assertFalse(p.allowsFontFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("object-src *", "http://example.com");
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsObjectFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsObjectFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsObjectFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com/PATH")));
        assertTrue(p.allowsObjectFromSource(URI.parse("ws://example.com/PATH")));
        assertTrue(p.allowsObjectFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsObjectFromSource(new GUID("data:")));
        assertFalse(p.allowsObjectFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("object-src http://*", "http://example.com");
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsObjectFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsObjectFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsObjectFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsObjectFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://example.com/PATH")));
        assertFalse(p.allowsObjectFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsObjectFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsObjectFromSource(new GUID("data:")));
        assertFalse(p.allowsObjectFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("object-src *.example.com", "http://example.com");
        assertTrue(p.allowsObjectFromSource(URI.parse("http://a.b.example.com/c/d")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://a.b.example.com")));
        assertTrue(p.allowsObjectFromSource(URI.parse("http://www.example.com")));
        assertFalse(p.allowsObjectFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsObjectFromSource(URI.parse("http://com")));
        assertFalse(p.allowsObjectFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsObjectFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsObjectFromSource(new GUID("data:")));
        assertFalse(p.allowsObjectFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("media-src *", "http://example.com");
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsMediaFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsMediaFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsMediaFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com/PATH")));
        assertTrue(p.allowsMediaFromSource(URI.parse("ws://example.com/PATH")));
        assertTrue(p.allowsMediaFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsMediaFromSource(new GUID("data:")));
        assertFalse(p.allowsMediaFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("media-src http://*", "http://example.com");
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsMediaFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsMediaFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsMediaFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsMediaFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://example.com/PATH")));
        assertFalse(p.allowsMediaFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsMediaFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsMediaFromSource(new GUID("data:")));
        assertFalse(p.allowsMediaFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("media-src *.example.com", "http://example.com");
        assertTrue(p.allowsMediaFromSource(URI.parse("http://a.b.example.com/c/d")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://a.b.example.com")));
        assertTrue(p.allowsMediaFromSource(URI.parse("http://www.example.com")));
        assertFalse(p.allowsMediaFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsMediaFromSource(URI.parse("http://com")));
        assertFalse(p.allowsMediaFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsMediaFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsMediaFromSource(new GUID("data:")));
        assertFalse(p.allowsMediaFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("manifest-src *", "http://example.com");
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsManifestFromSource(URI.parse("https://example.com")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com:81")));
        assertTrue(p.allowsManifestFromSource(URI.parse("ftp://example.com")));
        assertTrue(p.allowsManifestFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com/PATH")));
        assertTrue(p.allowsManifestFromSource(URI.parse("ws://example.com/PATH")));
        assertTrue(p.allowsManifestFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsManifestFromSource(new GUID("data:")));
        assertFalse(p.allowsManifestFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("manifest-src http://*", "http://example.com");
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsManifestFromSource(URI.parse("https://example.com")));
        assertFalse(p.allowsManifestFromSource(URI.parse("http://example.com:81")));
        assertFalse(p.allowsManifestFromSource(URI.parse("ftp://example.com")));
        assertFalse(p.allowsManifestFromSource(URI.parse("ftp://example.com:80")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com/path")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://example.com/PATH")));
        assertFalse(p.allowsManifestFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsManifestFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsManifestFromSource(new GUID("data:")));
        assertFalse(p.allowsManifestFromSource(new GUID("custom.scheme:")));
        
        p = Parser.parse("manifest-src *.example.com", "http://example.com");
        assertTrue(p.allowsManifestFromSource(URI.parse("http://a.b.example.com/c/d")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://a.b.example.com")));
        assertTrue(p.allowsManifestFromSource(URI.parse("http://www.example.com")));
        assertFalse(p.allowsManifestFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsManifestFromSource(URI.parse("http://com")));
        assertFalse(p.allowsManifestFromSource(URI.parse("ws://example.com/PATH")));
        assertFalse(p.allowsManifestFromSource(URI.parse("wss://example.com/PATH")));
        assertFalse(p.allowsManifestFromSource(new GUID("data:")));
        assertFalse(p.allowsManifestFromSource(new GUID("custom.scheme:")));
    }

    @Test public void testContainsSourceExpression() {
        Policy p;

        p = Parser.parse("", "http://example.com");
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        p = Parser.parse("default-src a 'self' 'unsafe-eval' 'unsafe-redirect' 'nonce-123' 'strict-dynamic' 'unsafe-inline'", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.Self));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.Self));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.Self));
        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));


        p = Parser.parse("script-src a 'self' 'unsafe-eval' 'nonce-123' 'unsafe-redirect' 'strict-dynamic' 'unsafe-inline'", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.Self));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        p = Parser.parse("style-src a 'self' 'unsafe-eval' 'unsafe-redirect' 'nonce-123' 'strict-dynamic' 'unsafe-inline'", "http://example.com");
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.Self));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x instanceof NonceSource));
        assertTrue(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(StyleSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.Self));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));

        p = Parser.parse("upgrade-insecure-requests", "http://example.com");
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeEval));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeInline));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.UnsafeRedirect));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x == KeywordSource.StrictDynamic));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x instanceof NonceSource));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "a", Constants.EMPTY_PORT, null))));
        assertFalse(p.containsSourceExpression(ImgSrcDirective.class, x -> x.equals(new HostSource(null, "b", Constants.EMPTY_PORT, null))));
    }

    @Test public void testDelimitersInHostSource() {
        Policy p;
        HostSource h;
        ScriptSrcDirective d;

        p = Parser.parse("script-src 'self'", "http://example.com");
        h = new HostSource(null, "example.com", Constants.EMPTY_PORT, "/a;jsessionid=123");
        d = new ScriptSrcDirective(Collections.singleton(h));
        p.unionDirective(d);
        assertEquals("script-src 'self' example.com/a%3Bjsessionid=123; worker-src 'self'", p.show());

        p = Parser.parse("script-src 'self'", "http://example.com");
        h = new HostSource(null, "example.com", Constants.EMPTY_PORT, "/a,b");
        d = new ScriptSrcDirective(Collections.singleton(h));
        p.unionDirective(d);
        assertEquals("script-src 'self' example.com/a%2Cb; worker-src 'self'", p.show());

        p = Parser.parse("script-src example.com/a%3Bjsessionid=123", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "example.com", Constants.EMPTY_PORT, "/a%3Bjsessionid=123"))));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "example.com", Constants.EMPTY_PORT, "/a;jsessionid=123"))));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "example.com", Constants.EMPTY_PORT, null))));

        p = Parser.parse("script-src example.com/a%2Cjsessionid=123", "http://example.com");
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "example.com", Constants.EMPTY_PORT, "/a%2Cjsessionid=123"))));
        assertTrue(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "example.com", Constants.EMPTY_PORT, "/a,jsessionid=123"))));
        assertFalse(p.containsSourceExpression(ScriptSrcDirective.class, x -> x.equals(new HostSource(null, "example.com", Constants.EMPTY_PORT, null))));
    }

    @Test public void testSourceExpressionStream() {
        Policy p;
        Stream<SourceExpression> s;

        p = Parser.parse("upgrade-insecure-requests", "http://example.com");
        s = p.getEffectiveSourceExpressions(DefaultSrcDirective.class);
        assertEquals(0, s.count());

        p = Parser.parse("script-src a b c", "http://example.com");
        s = p.getEffectiveSourceExpressions(ScriptSrcDirective.class);
        assertEquals(3, s.count());

        p = Parser.parse("script-src https: https://a.com http://b.com", "http://example.com");
        s = p.getEffectiveSourceExpressions(ScriptSrcDirective.class);
        assertEquals(2, s.filter(x -> x.show().startsWith("https")).count());

        p = Parser.parse("default-src https: https://a.com http://b.com", "http://example.com");
        s = p.getEffectiveSourceExpressions(ScriptSrcDirective.class);
        assertEquals(2, s.filter(x -> x.show().startsWith("https")).count());
    }

    @Test public void testEmptyPolicy() {
        Policy p;

        p = Parser.parse("", "http://example.com");
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("wss://example.com")));
        assertTrue(p.allowsScriptWithNonce(new Base64Value("1234")));
        assertTrue(p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512, new Base64Value(
            "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertTrue(p.allowsScriptFromSource(new GUID("custom.scheme:")));
        assertTrue(p.allowsScriptFromSource(new GUID("data:")));
    }

    @Test public void testHasSomeEffect() {
        Policy p = Parser.parse("", "http://example.com");
        assertFalse(p.hasSomeEffect());
        p = Parser.parse("script-src a; upgrade-insecure-requests; report-to a", "http://example.com");
        assertTrue(p.hasSomeEffect());
        p = Parser.parse("report-to a", "http://example.com");
        assertFalse(p.hasSomeEffect());
    }

    @Test public void testAllowsChild() {
        Policy p = Parser.parse("default-src 'none'; child-src 'self'", "http://example.com");
        assertTrue(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse("child-src 'none'; default-src 'self'", "http://example.com");
        assertFalse(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse(" default-src 'self'", "http://example.com");
        assertTrue(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse(" child-src 'self'", "http://example.com");
        assertTrue(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse(" child-src blob:", "http://example.com");
        assertTrue(p.allowsChildFromSource(new GUID("blob:")));
        assertFalse(p.allowsChildFromSource(new GUID("data:")));
    }

    @Test public void testAllowsWorker() {
        Policy p = Parser.parse("default-src 'none'; script-src 'self'", "http://example.com");
        assertFalse(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse("script-src 'none'; worker-src 'self'", "http://example.com");
        assertTrue(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertFalse(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse(" default-src 'self'", "http://example.com");
        assertTrue(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse(" script-src 'self'", "http://example.com");
        assertTrue(p.allowsChildFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsFrameFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsWorkerFromSource(URI.parse("http://example.com")));
        assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com")));

        p = Parser.parse(" worker-src blob:", "http://example.com");
        assertTrue(p.allowsWorkerFromSource(new GUID("blob:")));
        assertFalse(p.allowsWorkerFromSource(new GUID("data:")));
    }

    @Test public void testAllowNavigationTo() {
        Policy p = Parser.parse("navigate-to blob:", "http://example.com");
        assertTrue(p.allowsNavigation(new GUID("blob:")));
        assertFalse(p.allowsNavigation(new GUID("data:")));
        assertTrue(p.allowsFormAction(new GUID("blob:")));
        assertFalse(p.allowsFormAction(new GUID("data:")));

        p = Parser.parse("navigate-to blob:; form-action data:", "http://example.com");
        assertTrue(p.allowsNavigation(new GUID("blob:")));
        assertFalse(p.allowsNavigation(new GUID("data:")));
        assertTrue(p.allowsFormAction(new GUID("data:")));
        assertFalse(p.allowsFormAction(new GUID("blob:")));

        p = Parser.parse("form-action data:", "http://example.com");
        assertTrue(p.allowsNavigation(new GUID("blob:")));
        assertTrue(p.allowsNavigation(new GUID("data:")));
        assertTrue(p.allowsFormAction(new GUID("data:")));
        assertFalse(p.allowsFormAction(new GUID("blob:")));


        p = Parser.parse("navigate-to a", "http://example.com");
        assertTrue(p.allowsNavigation(URI.parse("http://a")));
        assertFalse(p.allowsNavigation(URI.parse("http://b")));
        assertTrue(p.allowsFormAction(URI.parse("http://a")));
        assertFalse(p.allowsFormAction(URI.parse("http://b")));

        p = Parser.parse("navigate-to a; form-action b", "http://example.com");
        assertTrue(p.allowsNavigation(URI.parse("http://a")));
        assertFalse(p.allowsNavigation(URI.parse("http://b")));
        assertTrue(p.allowsFormAction(URI.parse("http://b")));
        assertFalse(p.allowsFormAction(URI.parse("http://a")));

        p = Parser.parse("form-action a", "http://example.com");
        assertTrue(p.allowsNavigation(URI.parse("http://a")));
        assertTrue(p.allowsNavigation(URI.parse("http://b")));
        assertTrue(p.allowsFormAction(URI.parse("http://a")));
        assertFalse(p.allowsFormAction(URI.parse("http://b")));
    }
}
