package com.shapesecurity.csp;

import com.shapesecurity.csp.Parser.ParseException;
import com.shapesecurity.csp.Tokeniser.TokeniserException;
import com.shapesecurity.csp.directives.*;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.FileNotFoundException;
import java.util.Scanner;

import static org.junit.Assert.*;

public class ParserTest {
    private static int countIterable(Iterable<Directive<?>> a) {
        int count = 0;
        for (Object b : a) {
            ++count;
        }
        return count;
    }

    private String createAndShow(@Nonnull String value) throws ParseException, TokeniserException {
        return Parser.parse(value).getDirectiveByType(BaseUriDirective.class).show();
    }

    @Test
    public void testEmptyParser() throws ParseException, TokeniserException {
        Policy emptyPolicy = Parser.parse("");
        assertNotNull("empty policy should not be null", emptyPolicy);
    }

    @Test
    public void testTokeniser() throws ParseException, TokeniserException {
        failsToParse("_sand _box   ;   ");
    }

    @Test
    public void testDuplicates() throws ParseException, TokeniserException {
        Policy p;
        p = Parser.parse("img-src a ;;; img-src b");
        assertNotNull("policy should not be null", p);
        assertEquals("", 1, countIterable(p.getDirectives()));
        Directive<?> firstDirective = p.getDirectives().iterator().next();
        ImgSrcDirective imgSrcDirective = p.getDirectiveByType(ImgSrcDirective.class);
        assertEquals("", imgSrcDirective, firstDirective);
        assertEquals("", "img-src", ImgSrcDirective.name);
        assertEquals("", "img-src a", imgSrcDirective.show());
    }

    @Test
    public void testParser() throws ParseException, TokeniserException {

        Policy p = Parser.parse("font-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("form-action *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("frame-ancestors 'none'");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("frame-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("img-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("media-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("object-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("plugin-types */*");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("report-uri https://example.com/report");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("sandbox allow-scripts");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("script-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        p = Parser.parse("style-src *");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, countIterable(p.getDirectives()));
        failsToParse("abc");
        failsToParse("script-src *, ");
        failsToParse("zzscript-src *; bla");
    }

    private void failsToParse(String policy) {
        try {
            Parser.parse(policy);
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

        // XXX: these two tests are actually valid according to the CSP spec, but we choose not to support paths other than path-abempty
        failsToParse("base-uri abc_");
        failsToParse("base-uri abc..");

        assertEquals("directive-name, port-part", "base-uri *:12", createAndShow("base-uri *:12"));
        failsToParse("base-uri *:ee");
        assertEquals("directive-name, path-part", "base-uri */abc", createAndShow("base-uri */abc"));
        failsToParse("base-uri *\n");
        assertEquals("directive-name, full host source", "base-uri https://a.com:888/ert", createAndShow("base-uri https://a.com:888/ert"));

        assertEquals("directive-name, no directive-value", "child-src *", Parser.parse("child-src *").getDirectiveByType(ChildSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "connect-src *", Parser.parse("connect-src *").getDirectiveByType(ConnectSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "default-src *", Parser.parse("default-src *").getDirectiveByType(DefaultSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "font-src *", Parser.parse("font-src *").getDirectiveByType(FontSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "img-src *", Parser.parse("img-src *").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "media-src *", Parser.parse("media-src *").getDirectiveByType(MediaSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "object-src *", Parser.parse("object-src *").getDirectiveByType(ObjectSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "script-src *", Parser.parse("script-src *").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, no directive-value", "style-src *", Parser.parse("style-src *").getDirectiveByType(StyleSrcDirective.class).show());
    }

    @Test
    public void testAncestorSourceParsing() throws ParseException, TokeniserException {
        assertEquals("directive-name, no directive-value", "frame-ancestors", Parser.parse("frame-ancestors").getDirectiveByType(FrameAncestorsDirective.class).show());
        assertEquals("directive-name, directive-value", "frame-ancestors 'none'", Parser.parse("frame-ancestors 'none'").getDirectiveByType(FrameAncestorsDirective.class).show());

        Policy p;
        p = Parser.parse("frame-ancestors https://example.com");
        Policy q;
        q = Parser.parse("script-src abc; frame-ancestors http://example.com");
        FrameAncestorsDirective d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        FrameAncestorsDirective d2 = q.getDirectiveByType(FrameAncestorsDirective.class);
        ScriptSrcDirective d3 = q.getDirectiveByType(ScriptSrcDirective.class);

        d1.merge(d2);
        assertEquals("ancestor-source merge", "frame-ancestors https://example.com http://example.com", d1.show());
        assertFalse("ancestor-source inequality", d1.equals(d2));

        p = Parser.parse("frame-ancestors http://example.com");
        q = Parser.parse("frame-ancestors http://example.com");
        d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        d2 = q.getDirectiveByType(FrameAncestorsDirective.class);
        assertTrue("ancestor-source equality", d1.equals(d2));
        assertEquals("ancestor-source hashcode equality", d1.hashCode(), d2.hashCode());
        p = Parser.parse("frame-ancestors http:");
        q = Parser.parse("frame-ancestors http:");
        assertTrue("ancestor-source scheme-source equality", p.equals(q));
        assertEquals("ancestor-source scheme-source equality", p.hashCode(), q.hashCode());
    }

    @Test
    public void testPolicy() throws ParseException, TokeniserException {
        Policy p;
        p = Parser.parse("");
        assertEquals("policy show", "", p.show());
        p = Parser.parse("style-src *");
        assertEquals("policy show", "style-src *", p.show());
        Policy q;
        q = Parser.parse("style-src *");
        assertTrue("policy equality", p.equals(q));
        q = Parser.parse("script-src *");
        p.merge(q);
        assertEquals("policy merge", "style-src *; script-src *", p.show());

        q = Parser.parse("script-src abc");
        p.merge(q);
        assertEquals("policy merge", "style-src *; script-src * abc", p.show());
    }

    @Test()
    public void testPluginTypesParsing() throws ParseException, TokeniserException {
        failsToParse("plugin-types");
        // XXX: technically allowed via ietf-token if an RFC introduces a type/subtype that is empty
        failsToParse("plugin-types /");
        assertEquals("directive-name, directive-value", "plugin-types a/b", Parser.parse("plugin-types a/b").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d", Parser.parse("plugin-types a/b c/d").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types x-a/x-b", Parser.parse("plugin-types x-a/x-b").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types X-A/X-B", Parser.parse("plugin-types X-A/X-B").getDirectiveByType(PluginTypesDirective.class).show());

        Policy p;
        p = Parser.parse("plugin-types a/b");
        Policy q;
        q = Parser.parse("plugin-types c/d; script-src *");

        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);
        ScriptSrcDirective d3 = q.getDirectiveByType(ScriptSrcDirective.class);

        d1.merge(d2);
        assertEquals("plugin-types merge", "plugin-types a/b c/d", d1.show());
        p = Parser.parse("plugin-types a/b");
        q = Parser.parse("plugin-types a/c;");
        d1 = p.getDirectiveByType(PluginTypesDirective.class);
        d2 = q.getDirectiveByType(PluginTypesDirective.class);
        assertFalse("plugin-type subtype inequality", d1.equals(d2));
        p = Parser.parse("plugin-types a/b");
        q = Parser.parse("plugin-types a/b;");
        d1 = p.getDirectiveByType(PluginTypesDirective.class);
        d2 = q.getDirectiveByType(PluginTypesDirective.class);
        assertEquals("plugin-types hashcode equality", d1.hashCode(), d2.hashCode());
    }

    @Test
    public void testReportUri() throws ParseException, TokeniserException {
        failsToParse("report-uri ");
        Policy p;
        p = Parser.parse("report-uri a");
        Policy q;
        q = Parser.parse("report-uri b");
        ReportUriDirective d1 = p.getDirectiveByType(ReportUriDirective.class);
        assertFalse("report-uri inequality", d1.equals(q.getDirectiveByType(ReportUriDirective.class)));
        d1.merge(q.getDirectiveByType(ReportUriDirective.class));
        assertEquals("report-uri merge", "report-uri a b", d1.show());
        assertNotEquals("report-uri hashcode shouldn't match", p.hashCode(), q.hashCode());

        p = Parser.parse("report-uri  a");
        q = Parser.parse("report-uri a; ");
        assertEquals("report-uri hashcode match", p.hashCode(), q.hashCode());
        assertTrue("report-uri equals", p.equals(q));
        q = Parser.parse("report-uri a; sandbox 4");
        d1 = q.getDirectiveByType(ReportUriDirective.class);
        SandboxDirective d2 = q.getDirectiveByType(SandboxDirective.class);

    }

    @Test
    public void testMediaTypeMerge() throws ParseException, TokeniserException {
        Policy p;
        p = Parser.parse("plugin-types a/b");
        Policy q;
        q = Parser.parse("plugin-types c/d");
        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);
        d1.merge(d2);
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d", d1.show());
    }

    @Test
    public void testSandboxParsing() throws ParseException, TokeniserException {
        failsToParse("sandbox a!*\n");
        failsToParse("sandbox a!*^:");
        assertEquals("sandbox is valid", "sandbox abc", Parser.parse("sandbox abc").getDirectiveByType(SandboxDirective.class).show());
        Policy p;
        p = Parser.parse("sandbox a");
        Policy q;
        q = Parser.parse("sandbox a");
        SandboxDirective d1 = p.getDirectiveByType(SandboxDirective.class);
        assertTrue("sandbox equals", d1.equals(q.getDirectiveByType(SandboxDirective.class)));
        assertEquals("sandbox hashcode equality", p.hashCode(), q.hashCode());
        q = Parser.parse("sandbox b; script-src a");
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
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'sha256-RUM5'", Parser.parse("script-src 'self' https://example.com 'sha256-RUM5'").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'sha384-RUM5'", Parser.parse("script-src 'self' https://example.com 'sha384-RUM5'").getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'sha512-RUM5'", Parser.parse("script-src 'self' https://example.com 'sha512-RUM5'").getDirectiveByType(ScriptSrcDirective.class).show());
        Policy p = Parser.parse("script-src 'sha512-RUM5'");
        Policy q = Parser.parse("script-src 'sha512-RUM5'");
        assertEquals("hash-source hashcode equality", p.hashCode(), q.hashCode());
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("hash-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = Parser.parse("script-src 'sha512-eHV5'");
        assertFalse("hash-source inequality", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
    }

    @Test
    public void sourceListTest() throws ParseException, TokeniserException {
        Policy p = Parser.parse("script-src http://a https://b; style-src http://e");
        Policy q = Parser.parse("script-src c d");
        ScriptSrcDirective d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        assertFalse("source-list inequality", d1.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        d1.merge(q.getDirectiveByType(ScriptSrcDirective.class));
        assertEquals("source-list merge", "script-src http://a https://b c d", d1.show());
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
        p = Parser.parse("script-src http://a https://b");
        q = Parser.parse("script-src http://a https://b");
        d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("source-list equality", d1.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        assertEquals("source-list hashcode equality", p.hashCode(), q.hashCode());
    }

    @Test
    public void testNonceSource() throws ParseException, TokeniserException {
        failsToParse("script-src 'self' https://example.com 'nonce-Nc3n83cnSAd3wc3Sasdfn939hc3'");
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'nonce-MTIzNDU2Nw=='", Parser.parse("script-src 'self' https://example.com 'nonce-MTIzNDU2Nw=='").getDirectiveByType(ScriptSrcDirective.class).show());
        Policy p = Parser.parse("script-src 'nonce-MTIzNDU2Nw=='");
        Policy q = Parser.parse("script-src 'nonce-MTIzNDU2Nw=='");
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertEquals("hash code matches", p.hashCode(), q.hashCode());
        assertTrue("nonce-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = Parser.parse("script-src 'nonce-aGVsbG8gd29ybGQ='");
        assertFalse("sandbox !equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
    }

    @Test
    public void testBase64Value() throws ParseException, TokeniserException {
        assertEquals("directive-name, directive-value", "script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='", Parser.parse("script-src 'self' https://example.com 'nonce-aGVsbG8gd29ybGQ='").getDirectiveByType(ScriptSrcDirective.class).show());
        failsToParse("script-src 'self' https://example.com 'nonce-123'"); // illegal length
        failsToParse("script-src 'self' https://example.com 'nonce-123^'"); // illegal chars
        failsToParse("script-src 'self' https://example.com 'nonce-12=+'"); // illegal padding
        failsToParse("script-src 'self' https://example.com 'nonce-1^=='"); // illegal chars
        failsToParse("script-src 'self' https://example.com 'nonce-1==='"); // illegal chars


    }

    @Test
    public void testKeywordSource() throws ParseException, TokeniserException {
        assertEquals("directive-name, directive-value", "img-src example.com 'self'", Parser.parse("img-src example.com 'self'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-inline'", Parser.parse("img-src example.com 'unsafe-inline'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-eval'", Parser.parse("img-src example.com 'unsafe-eval'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-redirect'", Parser.parse("img-src example.com 'unsafe-redirect'").getDirectiveByType(ImgSrcDirective.class).show());
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
                    p = Parser.parse(line[1]);
                    assertNotNull(String.format("policy should not be null: %s", line[0]), p);
                } catch (ParseException | TokeniserException e) {
                    System.out.println(line[0]);
                    System.out.println(e);
                }
            }
        }
    }
}
