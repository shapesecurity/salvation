package com.shapesecurity.csp;

import com.shapesecurity.csp.Parser.ParseException;
import com.shapesecurity.csp.Tokeniser.TokeniserException;
import com.shapesecurity.csp.directives.*;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.FileNotFoundException;
import java.util.Scanner;

import static org.junit.Assert.*;

@SuppressWarnings("ConstantConditions")
public class ParserTest {
    private static int countIterable(Iterable<Directive<?>> a) {
        int count = 0;
        for (Object b : a) {
            ++count;
        }
        return count;
    }

    @Nonnull
    private static Policy createPolicyWithDefaultOrigin(@Nonnull String policy) throws ParseException, TokeniserException {
        return Parser.parse(policy, "http://example.com");
    }
    private String createAndShow(@Nonnull String value) throws ParseException, TokeniserException {
        return createPolicyWithDefaultOrigin(value).getDirectiveByType(BaseUriDirective.class).show();
    }

    @Test
    public void testEmptyParser() throws ParseException, TokeniserException {
        Policy emptyPolicy = createPolicyWithDefaultOrigin("");
        assertNotNull("empty policy should not be null", emptyPolicy);
    }

    @Test
    public void testTokeniser() throws ParseException, TokeniserException {
        failsToParse("_sand _box   ;   ");
    }

    @Test
    public void testDuplicates() throws ParseException, TokeniserException {
        Policy p;
        p = createPolicyWithDefaultOrigin("img-src a ;;; img-src b");
        assertNotNull("policy should not be null", p);
        assertEquals("", 1, countIterable(p.getDirectives()));
        Directive<?> firstDirective = p.getDirectives().iterator().next();
        ImgSrcDirective imgSrcDirective = p.getDirectiveByType(ImgSrcDirective.class);
        assertTrue(firstDirective instanceof ImgSrcDirective);
        assertEquals("", imgSrcDirective, (ImgSrcDirective) firstDirective);
        assertEquals("", "img-src", ImgSrcDirective.name);
        assertEquals("", "img-src a", imgSrcDirective.show());
    }

    @Test
    public void testParser() throws ParseException, TokeniserException {

        Policy p = createPolicyWithDefaultOrigin("font-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("form-action *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("frame-ancestors 'none'");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("frame-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("img-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("media-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("object-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("plugin-types */*");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("report-uri https://example.com/report");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("sandbox allow-scripts");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("script-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = createPolicyWithDefaultOrigin("style-src http://*.example.com:*");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        failsToParse("abc");
        failsToParse("script-src *, ");
        failsToParse("zzscript-src *; bla");

        p = createPolicyWithDefaultOrigin("style-src *");
        Policy q = createPolicyWithDefaultOrigin("script-src *");
        StyleSrcDirective d1 = p.getDirectiveByType(StyleSrcDirective.class);
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
        try {
            d1.merge(d2);
        } catch (IllegalArgumentException e) {
            assertEquals("class com.shapesecurity.csp.directives.StyleSrcDirective can be merged with class com.shapesecurity.csp.directives.StyleSrcDirective, but found class com.shapesecurity.csp.directives.ScriptSrcDirective", e.getMessage());
        }
    }

    private void failsToParse(String policy) {
        try {
            createPolicyWithDefaultOrigin(policy);
        } catch (ParseException | TokeniserException | IllegalArgumentException ignored) {
            return;
        }
        fail();
    }

    @Test
    public void testSourceExpressionParsing() throws ParseException, TokeniserException {
        assertEquals("directive-name, no directive-value", "base-uri", createAndShow("base-uri"));
        assertEquals("directive-name, <tab>", "base-uri", createAndShow("base-uri\t"));
        assertEquals("directive-name, <space>", "base-uri", createAndShow("base-uri "));
        assertEquals("directive-name, 3*<space>", "base-uri", createAndShow("base-uri   "));
        assertEquals("directive-name, scheme-part", "base-uri https:", createAndShow("base-uri https:"));
        assertEquals("directive-name, 2*scheme-part", "base-uri file: javascript:", createAndShow("base-uri file: javascript: "));
        assertEquals("directive-name, host-part *", "base-uri *", createAndShow("base-uri *"));
        assertEquals("directive-name, host-part *.", "base-uri *.a", createAndShow("base-uri *.a"));

        failsToParse("connect-src 'none' scheme:");
        failsToParse("connect-src scheme: 'none'");

        // XXX: these two tests are actually valid according to the CSP spec, but we choose not to support paths other than path-abempty
        failsToParse("base-uri abc_");
        failsToParse("base-uri abc..");

        assertEquals("directive-name, port-part", "base-uri *:12", createAndShow("base-uri *:12"));
        failsToParse("base-uri *:ee");
        assertEquals("directive-name, path-part", "base-uri */abc", createAndShow("base-uri */abc"));
        failsToParse("base-uri *\n");
        assertEquals("directive-name, full host source", "base-uri https://a.com:888/ert", createAndShow("base-uri https://a.com:888/ert"));

        assertEquals("directive-name, no directive-value", "child-src *", createPolicyWithDefaultOrigin("child-src *").getDirectiveByType(ChildSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "connect-src *", createPolicyWithDefaultOrigin("connect-src *").getDirectiveByType(ConnectSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "default-src *", createPolicyWithDefaultOrigin("default-src *").getDirectiveByType(DefaultSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "font-src *", createPolicyWithDefaultOrigin("font-src *").getDirectiveByType(FontSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "img-src *", createPolicyWithDefaultOrigin("img-src *").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "media-src *", createPolicyWithDefaultOrigin("media-src *").getDirectiveByType(MediaSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "object-src *", createPolicyWithDefaultOrigin("object-src *").getDirectiveByType(ObjectSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "script-src *", createPolicyWithDefaultOrigin("script-src *").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "style-src *", createPolicyWithDefaultOrigin("style-src *").getDirectiveByType(StyleSrcDirective.class).show());
    }

    @Test
    public void testAncestorSourceParsing() throws ParseException, TokeniserException {
        assertEquals("directive-name, no directive-value", "frame-ancestors", createPolicyWithDefaultOrigin("frame-ancestors").getDirectiveByType(FrameAncestorsDirective.class).show());
        assertEquals("directive-name, directive-value", "frame-ancestors 'none'", createPolicyWithDefaultOrigin("frame-ancestors 'none'").getDirectiveByType(FrameAncestorsDirective.class).show());

        Policy p;
        p = createPolicyWithDefaultOrigin("frame-ancestors https://example.com");
        Policy q;
        q = createPolicyWithDefaultOrigin("script-src abc; frame-ancestors http://example.com");
        FrameAncestorsDirective d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        FrameAncestorsDirective d2 = q.getDirectiveByType(FrameAncestorsDirective.class);
        ScriptSrcDirective d3 = q.getDirectiveByType(ScriptSrcDirective.class);

        d1.merge(d2);
        assertEquals("ancestor-source merge", "frame-ancestors https://example.com http://example.com", d1.show());
        assertFalse("ancestor-source inequality", d1.equals(d2));

        p = createPolicyWithDefaultOrigin("frame-ancestors http://example.com");
        q = createPolicyWithDefaultOrigin("frame-ancestors http://example.com");
        d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        d2 = q.getDirectiveByType(FrameAncestorsDirective.class);
        assertTrue("ancestor-source equality", d1.equals(d2));
        assertEquals("ancestor-source hashcode equality", d1.hashCode(), d2.hashCode());
        p = createPolicyWithDefaultOrigin("frame-ancestors http:");
        q = createPolicyWithDefaultOrigin("frame-ancestors http:");
        assertTrue("ancestor-source scheme-source equality", p.equals(q));
        assertEquals("ancestor-source scheme-source equality", p.hashCode(), q.hashCode());

        failsToParse("frame-ancestors scheme::");
    }

    @Test
    public void testPolicy() throws ParseException, TokeniserException {
        Policy p;
        p = createPolicyWithDefaultOrigin("");
        assertEquals("policy show", "", p.show());
        p = createPolicyWithDefaultOrigin("style-src *");
        assertEquals("policy show", "style-src *", p.show());
        Policy q;
        q = createPolicyWithDefaultOrigin("style-src *");
        assertTrue("policy equality", p.equals(q));
        q = createPolicyWithDefaultOrigin("script-src *");
        p.merge(q);
        assertEquals("policy merge", "style-src *; script-src *", p.show());

        q = createPolicyWithDefaultOrigin("script-src abc");
        p.merge(q);
        assertEquals("policy merge", "style-src *; script-src * abc", p.show());
    }

    @Test()
    public void testPluginTypesParsing() throws ParseException, TokeniserException {
        failsToParse("plugin-types");
        // XXX: technically allowed via ietf-token if an RFC introduces a type/subtype that is empty
        failsToParse("plugin-types /");
        assertEquals("directive-name, directive-value", "plugin-types a/b", createPolicyWithDefaultOrigin("plugin-types a/b").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d", createPolicyWithDefaultOrigin("plugin-types a/b c/d").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types x-a/x-b", createPolicyWithDefaultOrigin("plugin-types x-a/x-b").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types X-A/X-B", createPolicyWithDefaultOrigin("plugin-types X-A/X-B").getDirectiveByType(PluginTypesDirective.class).show());

        Policy p;
        p = createPolicyWithDefaultOrigin("plugin-types a/b");
        Policy q;
        q = createPolicyWithDefaultOrigin("plugin-types c/d; script-src *");

        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);
        ScriptSrcDirective d3 = q.getDirectiveByType(ScriptSrcDirective.class);

        d1.merge(d2);
        assertEquals("plugin-types merge", "plugin-types a/b c/d", d1.show());
        p = createPolicyWithDefaultOrigin("plugin-types a/b");
        q = createPolicyWithDefaultOrigin("plugin-types a/c;");
        d1 = p.getDirectiveByType(PluginTypesDirective.class);
        d2 = q.getDirectiveByType(PluginTypesDirective.class);
        assertFalse("plugin-type subtype inequality", d1.equals(d2));
        p = createPolicyWithDefaultOrigin("plugin-types a/b");
        q = createPolicyWithDefaultOrigin("plugin-types a/b;");
        d1 = p.getDirectiveByType(PluginTypesDirective.class);
        d2 = q.getDirectiveByType(PluginTypesDirective.class);
        assertEquals("plugin-types hashcode equality", d1.hashCode(), d2.hashCode());
    }

    @Test
    public void testReportUri() throws ParseException, TokeniserException {
        failsToParse("report-uri ");
        failsToParse("report-uri #");
        failsToParse("report-uri a");
        Policy p;
        p = createPolicyWithDefaultOrigin("report-uri http://a");
        Policy q;
        q = createPolicyWithDefaultOrigin("report-uri http://b");
        ReportUriDirective d1 = p.getDirectiveByType(ReportUriDirective.class);
        assertFalse("report-uri inequality", d1.equals(q.getDirectiveByType(ReportUriDirective.class)));
        d1.merge(q.getDirectiveByType(ReportUriDirective.class));
        assertEquals("report-uri merge", "report-uri http://a http://b", d1.show());
        assertNotEquals("report-uri hashcode shouldn't match", p.hashCode(), q.hashCode());

        // TODO relative URI is legal ?
        //p = createPolicyWithDefaultOrigin("report-uri  a");
        //q = createPolicyWithDefaultOrigin("report-uri a; ");
        p = createPolicyWithDefaultOrigin("report-uri  https://a");
        q = createPolicyWithDefaultOrigin("report-uri https://a; ");
        assertEquals("report-uri hashcode match", p.hashCode(), q.hashCode());
        assertTrue("report-uri equals", p.equals(q));
        q = createPolicyWithDefaultOrigin("report-uri http://a; sandbox 4");
        d1 = q.getDirectiveByType(ReportUriDirective.class);
        SandboxDirective d2 = q.getDirectiveByType(SandboxDirective.class);
        assertEquals("report-uri http://a", d1.show());
        assertEquals("sandbox 4", d2.show());

    }

    @Test
    public void testMediaTypeMerge() throws ParseException, TokeniserException {
        Policy p;
        p = createPolicyWithDefaultOrigin("plugin-types a/b");
        Policy q;
        q = createPolicyWithDefaultOrigin("plugin-types c/d");
        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);
        d1.merge(d2);
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d", d1.show());
    }

    @Test
    public void testSandboxParsing() throws ParseException, TokeniserException {
        failsToParse("sandbox a!*\n");
        failsToParse("sandbox a!*^:");
        assertEquals("sandbox is valid", "sandbox abc", createPolicyWithDefaultOrigin("sandbox abc").getDirectiveByType(SandboxDirective.class).show());
        Policy p;
        p = createPolicyWithDefaultOrigin("sandbox a");
        Policy q;
        q = createPolicyWithDefaultOrigin("sandbox a");
        SandboxDirective d1 = p.getDirectiveByType(SandboxDirective.class);
        assertTrue("sandbox equals", d1.equals(q.getDirectiveByType(SandboxDirective.class)));
        assertEquals("sandbox hashcode equality", p.hashCode(), q.hashCode());
        q = createPolicyWithDefaultOrigin("sandbox b; script-src a");
        assertFalse("sandbox directives equality", d1.equals(q.getDirectiveByType(SandboxDirective.class)));
        d1.merge(q.getDirectiveByType(SandboxDirective.class));
        assertEquals("sandbox merge", "sandbox a b", d1.show());
        assertNotEquals("sandbox hashcode inequality", p.hashCode(), q.hashCode());
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
    }

    @Test
    public void testHashSource() throws ParseException, TokeniserException {
        failsToParse("script-src 'self' https://example.com 'sha255-RUM5'");
        failsToParse("script-src 'self' https://example.com 'sha256-333'");
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'sha256-RUM5'", createPolicyWithDefaultOrigin("script-src 'self' https://example.com 'sha256-RUM5'").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'sha384-RUM5'", createPolicyWithDefaultOrigin("script-src 'self' https://example.com 'sha384-RUM5'").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'sha512-RUM5'", createPolicyWithDefaultOrigin("script-src 'self' https://example.com 'sha512-RUM5'").getDirectiveByType(ScriptSrcDirective.class).show());
        Policy p = createPolicyWithDefaultOrigin("script-src 'sha512-RUM5'");
        Policy q = createPolicyWithDefaultOrigin("script-src 'sha512-RUM5'");
        assertEquals("hash-source hashcode equality", p.hashCode(), q.hashCode());
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("hash-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = createPolicyWithDefaultOrigin("script-src 'sha512-eHV5'");
        assertFalse("hash-source inequality", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
    }

    @Test
    public void sourceListTest() throws ParseException, TokeniserException {
        Policy p = createPolicyWithDefaultOrigin("script-src http://a https://b; style-src http://e");
        Policy q = createPolicyWithDefaultOrigin("script-src c d");
        ScriptSrcDirective d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        assertFalse("source-list inequality", d1.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        d1.merge(q.getDirectiveByType(ScriptSrcDirective.class));
        assertEquals("source-list merge", "script-src http://a https://b c d", d1.show());
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
        p = createPolicyWithDefaultOrigin("script-src http://a https://b");
        q = createPolicyWithDefaultOrigin("script-src http://a https://b");
        d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("source-list equality", d1.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        assertEquals("source-list hashcode equality", p.hashCode(), q.hashCode());
    }

    @Test
    public void testNonceSource() throws ParseException, TokeniserException {
        failsToParse("script-src 'self' https://example.com 'nonce-Nc3n83cnSAd3wc3Sasdfn939hc3'");
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'nonce-MTIzNDU2Nw=='", createPolicyWithDefaultOrigin("script-src 'self' https://example.com 'nonce-MTIzNDU2Nw=='").getDirectiveByType(ScriptSrcDirective.class).show());
        Policy p = createPolicyWithDefaultOrigin("script-src 'nonce-MTIzNDU2Nw=='");
        Policy q = createPolicyWithDefaultOrigin("script-src 'nonce-MTIzNDU2Nw=='");
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertEquals("hash code matches", p.hashCode(), q.hashCode());
        assertTrue("nonce-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = createPolicyWithDefaultOrigin("script-src 'nonce-aGVsbG8gd29ybGQ='");
        assertFalse("sandbox !equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
    }

    @Test
    public void testBase64Value() throws ParseException, TokeniserException {
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='", createPolicyWithDefaultOrigin("script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='").getDirectiveByType(ScriptSrcDirective.class).show());
        failsToParse("script-src 'self' https://example.com 'nonce-123'"); // illegal length
        failsToParse("script-src 'self' https://example.com 'nonce-123^'"); // illegal chars
        failsToParse("script-src 'self' https://example.com 'nonce-12=+'"); // illegal padding
        failsToParse("script-src 'self' https://example.com 'nonce-1^=='"); // illegal chars
        failsToParse("script-src 'self' https://example.com 'nonce-1==='"); // illegal chars


    }

    @Test
    public void testKeywordSource() throws ParseException, TokeniserException {
        assertEquals("directive-name, directive-value", "img-src example.com 'self'", createPolicyWithDefaultOrigin("img-src example.com 'self'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-inline'", createPolicyWithDefaultOrigin("img-src example.com 'unsafe-inline'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-eval'", createPolicyWithDefaultOrigin("img-src example.com 'unsafe-eval'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-redirect'", createPolicyWithDefaultOrigin("img-src example.com 'unsafe-redirect'").getDirectiveByType(ImgSrcDirective.class).show());
    }

    @Test
    public void testContains() throws ParseException, TokeniserException {
        Policy p = createPolicyWithDefaultOrigin("script-src a b c");
        Policy q = createPolicyWithDefaultOrigin("script-src a");
        Policy r = createPolicyWithDefaultOrigin("script-src m");
        Policy s = createPolicyWithDefaultOrigin("report-uri /z");
        ScriptSrcDirective d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
        DirectiveValue value = d2.values().iterator().next();
        assertTrue("directive contains", d1.contains(value));
        ScriptSrcDirective d3 = r.getDirectiveByType(ScriptSrcDirective.class);
        value = d3.values().iterator().next();
        assertFalse("directive doesn't contain", d1.contains(value));
        ReportUriDirective d4 = s.getDirectiveByType(ReportUriDirective.class);
        value = d3.values().iterator().next();
        assertFalse("directive doesn't contain", d1.contains(value));
    }

    @Test
    public void testMatches() throws ParseException, TokeniserException, IllegalArgumentException {
        Policy p = Parser.parse("img-src https: 'self' http://abc.am/; style-src https://*.abc.am:*", "https://abc.com");
        assertTrue("resource is allowed", p.allowsImageFromSource(URI.parse("https://a.com/12")));
        assertTrue("resource is allowed", p.allowsImageFromSource(URI.parse("https://abc.am")));
        assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parse("ftp://www.abc.am:555")));

        assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
        assertFalse("resource is not allowed", p.allowsImageFromSource(URI.parse("http://a.com/12")));

        p = Parser.parse("script-src https: 'self' http://a 'unsafe-inline'", URI.parse("https://abc.com"));
        assertTrue("inline script is allowed", p.allowsUnsafeInlineScript());

        //assertTrue("plugin is allowed", createPolicyWithDefaultOrigin("plugin-types a/b c/d").allowsPlugin(new MediaTypeListDirective.MediaType("a", "b")));
    }

    @Test
    public void testRealData() throws FileNotFoundException, ParseException, TokeniserException {
        Scanner sc = new Scanner(this.getClass().getClassLoader().getResourceAsStream("csp.txt"));
        while (sc.hasNextLine()) {
            Policy p;
            String[] line = sc.nextLine().split(":", 2);
            // do not process commented lines
            if (!line[0].startsWith("//")) {
                try {
                    p = createPolicyWithDefaultOrigin(line[1]);
                    assertNotNull(String.format("policy should not be null: %s", line[0]), p);
                } catch (ParseException | TokeniserException e) {
                    System.out.println(line[0]);
                    System.out.println(e);
                }
            }
        }
    }
}
