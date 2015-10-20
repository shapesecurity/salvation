package com.shapesecurity.salvation;

import com.shapesecurity.salvation.Parser.ParseException;
import com.shapesecurity.salvation.Tokeniser.TokeniserException;
import com.shapesecurity.salvation.data.Base64Value;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.data.Warning;
import com.shapesecurity.salvation.directiveValues.HashSource;

import com.shapesecurity.salvation.directives.*;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.util.*;

import static org.junit.Assert.*;

public class ParserTest extends CSPTest {

    @Test
    public void testEmptyPolicy() throws ParseException, TokeniserException {
        Policy p = parse("");
        assertNotNull("empty policy should not be null", p);
        assertTrue("resource is allowed",
            p.allowsScriptFromSource(URI.parse("https://www.def.am")));
        assertTrue("resource is allowed", p.allowsScriptWithHash(HashSource.HashAlgorithm.SHA512,
            new Base64Value(
                "vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==")));
        assertTrue("resource is allowed", p.allowsScriptWithNonce(new Base64Value("0gQAAA==")));
    }

    @Test
    public void testTokeniser() {
        try {
            Tokeniser.tokenise("_sand _box   ;   ");
            fail();
        } catch (TokeniserException ignored) { }
    }

    @Test
    public void testDuplicates() throws ParseException, TokeniserException {
        Policy p;
        p = parse("img-src a ;;; img-src b");
        assertNotNull("policy should not be null", p);
        assertEquals("", 1, p.getDirectives().size());
        Directive<?> firstDirective = p.getDirectives().iterator().next();
        ImgSrcDirective imgSrcDirective = p.getDirectiveByType(ImgSrcDirective.class);
        assertNotNull(imgSrcDirective);
        assertTrue(firstDirective instanceof ImgSrcDirective);
        assertEquals("", imgSrcDirective, (ImgSrcDirective) firstDirective);
        assertEquals("", "img-src", ImgSrcDirective.name);
        assertEquals("", "img-src a", imgSrcDirective.show());
    }

    @Test
    public void testDirectiveNameParsing() throws ParseException, TokeniserException {
        Policy p;

        p = parse("font-src a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("form-action a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("frame-ancestors 'none'");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("frame-src a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("img-src a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("media-src a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("object-src a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("plugin-types */*");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("report-uri https://example.com/report");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("sandbox allow-scripts");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("script-src a");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("style-src http://*.example.com:*");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("style-src samba://*.example.com");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        failsToParse("abc");
        failsToParse("zzscript-src *; bla");
    }

    @Test
    public void testSourceExpressionParsing() throws ParseException, TokeniserException {
        assertEquals("directive-name, no directive-value", "base-uri", parseAndShow("base-uri"));
        assertEquals("directive-name, <tab>", "base-uri", parseAndShow("base-uri\t"));
        assertEquals("directive-name, <space>", "base-uri", parseAndShow("base-uri "));
        assertEquals("directive-name, 3*<space>", "base-uri", parseAndShow("base-uri   "));
        assertEquals("directive-name, scheme-part", "base-uri https:", parseAndShow("base-uri https:"));
        assertEquals("directive-name, 2*scheme-part", "base-uri file: javascript:", parseAndShow("base-uri file: javascript: "));
        assertEquals("directive-name, eliminated scheme-part", "base-uri *", parseAndShow(
            "base-uri * https:"));
        assertEquals("directive-name, host-part *", "base-uri *", parseAndShow("base-uri *"));
        assertEquals("directive-name, host-part *.", "base-uri *.a", parseAndShow("base-uri *.a"));

        assertEquals("represent origin host-source as 'self' keyword-source", "default-src 'self'",
            parse("default-src http://example.com").show());

        failsToParse("connect-src 'none' scheme:");
        failsToParse("connect-src scheme: 'none'");

        // XXX: these two tests are actually valid according to the CSP spec, but we choose not to support paths other than path-abempty
        failsToParse("base-uri abc_");
        failsToParse("base-uri abc..");

        assertEquals("directive-name, port-part", "base-uri *:12", parseAndShow("base-uri *:12"));
        failsToParse("base-uri *:ee");
        assertEquals("directive-name, path-part", "base-uri */abc", parseAndShow("base-uri */abc"));
        failsToParse("base-uri *\n");
        assertEquals("directive-name, full host source", "base-uri https://a.com:888/ert",
            parseAndShow("base-uri https://a.com:888/ert"));

        assertEquals("directive-name, host-source *:*", "script-src *:*", parseAndShow("script-src *:*"));
        assertEquals("directive-name, host-source a:*", "script-src a:*", parseAndShow("script-src a:*"));
        assertEquals("directive-name, host-source http://a:*", "script-src http://a:*", parseAndShow("script-src http://a:*"));

        assertEquals("optimisation", "", parseAndShow("script-src example.com *"));
        assertEquals("optimisation", "", parseAndShow("script-src 'self' *"));
        assertEquals("optimisation", "script-src 'unsafe-inline'; style-src 'unsafe-inline'", parseAndShow("script-src 'unsafe-inline'; style-src 'unsafe-inline';"));


    }

    @Test
    public void testAncestorSource() throws ParseException, TokeniserException {
        assertEquals("directive-name, no directive-value", "frame-ancestors",
            parse("frame-ancestors")
                .getDirectiveByType(FrameAncestorsDirective.class).show());
        assertEquals("directive-name, directive-value", "frame-ancestors 'none'",
            parse("frame-ancestors 'none'")
                .getDirectiveByType(FrameAncestorsDirective.class).show());

        Policy p;
        p = parse("frame-ancestors 'self' https://example.com");
        Policy q;
        q = parse("script-src abc; frame-ancestors http://example.com");
        FrameAncestorsDirective d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        FrameAncestorsDirective d2 = q.getDirectiveByType(FrameAncestorsDirective.class);

        d1.union(d2);
        assertEquals("ancestor-source union",
            "frame-ancestors 'self' https://example.com http://example.com", d1.show());
        assertFalse("ancestor-source inequality", d1.equals(d2));

        p = parse("frame-ancestors http://example.com");
        q = parse("frame-ancestors http://example.com");
        d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        d2 = q.getDirectiveByType(FrameAncestorsDirective.class);
        assertTrue("ancestor-source equality", d1.equals(d2));
        assertEquals("ancestor-source hashcode equality", d1.hashCode(), d2.hashCode());
        p = parse("frame-ancestors http:");
        q = parse("frame-ancestors http:");
        assertTrue("ancestor-source scheme-source equality", p.equals(q));
        assertEquals("ancestor-source scheme-source equality", p.hashCode(), q.hashCode());

        failsToParse("frame-ancestors scheme::");
        failsToParse("frame-ancestors 'none' 'self'");

        p = parse("frame-ancestors *");
        q = parse("frame-ancestors http://example.com");
        p.union(q);
        assertEquals("frame-ancestors *", p.show());
    }

    @Test
    public void testPolicy() throws ParseException, TokeniserException {
        Policy a = parse("");
        assertEquals("policy show", "", a.show());

        Policy b = parse("style-src *");
        assertEquals("policy show", "", b.show());

        assertTrue("policy equality", a.equals(b));

        Policy c = parse("script-src *");
        b.union(c);
        assertEquals("policy union", "", b.show());

        Policy d = parse("script-src abc");
        b.union(d);
        assertEquals("policy union", "", b.show());

        a.setOrigin(URI.parse("http://qwe.zz:80"));
        assertEquals("policy origin", "http://qwe.zz", a.getOrigin().show());
    }

    @Test() public void testPluginTypesParsing() throws ParseException, TokeniserException {
        failsToParse("plugin-types");
        // XXX: technically allowed via ietf-token if an RFC introduces a type/subtype that is empty
        failsToParse("plugin-types /");
        assertEquals("directive-name, directive-value", "plugin-types a/b",
            parse("plugin-types a/b")
                .getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d",
            parse("plugin-types a/b c/d")
                .getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types x-a/x-b",
            parse("plugin-types x-a/x-b")
                .getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types X-A/X-B",
            parse("plugin-types X-A/X-B")
                .getDirectiveByType(PluginTypesDirective.class).show());

        Policy p, q;
        p = parse("plugin-types a/b");
        q = parse("plugin-types c/d; script-src *");

        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);

        d1.union(d2);
        assertEquals("plugin-types union", "plugin-types a/b c/d", d1.show());
        p = parse("plugin-types a/b");
        q = parse("plugin-types a/c;");
        d1 = p.getDirectiveByType(PluginTypesDirective.class);
        d2 = q.getDirectiveByType(PluginTypesDirective.class);
        assertFalse("plugin-type subtype inequality", d1.equals(d2));
        p = parse("plugin-types a/b");
        q = parse("plugin-types a/b;");
        d1 = p.getDirectiveByType(PluginTypesDirective.class);
        d2 = q.getDirectiveByType(PluginTypesDirective.class);
        assertEquals("plugin-types hashcode equality", d1.hashCode(), d2.hashCode());
    }

    @Test
    public void testReportUri() throws ParseException, TokeniserException {
        failsToParse("report-uri ");
        failsToParse("report-uri #");
        failsToParse("report-uri a");
        Policy p, q;
        p = parse("report-uri http://a");
        q = parse("report-uri http://b");
        ReportUriDirective d1 = p.getDirectiveByType(ReportUriDirective.class);
        assertFalse("report-uri inequality", d1.equals(q.getDirectiveByType(ReportUriDirective.class)));
        d1.union(q.getDirectiveByType(ReportUriDirective.class));
        assertEquals("report-uri union", "report-uri http://a http://b", d1.show());
        assertNotEquals("report-uri hashcode shouldn't match", p.hashCode(), q.hashCode());
        
        p = parse("report-uri  https://a");
        q = parse("report-uri https://a; ");
        assertEquals("report-uri hashcode match", p.hashCode(), q.hashCode());
        assertTrue("report-uri equals", p.equals(q));
        q = parse("report-uri http://a; sandbox 4");
        d1 = q.getDirectiveByType(ReportUriDirective.class);
        SandboxDirective d2 = q.getDirectiveByType(SandboxDirective.class);
        assertEquals("report-uri http://a", d1.show());
        assertEquals("sandbox 4", d2.show());

    }

    @Test
    public void testMediaTypeUnion() throws ParseException, TokeniserException {
        Policy p;
        p = parse("plugin-types a/b");
        Policy q;
        q = parse("plugin-types c/d");
        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);
        d1.union(d2);
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d", d1.show());
    }

    @Test
    public void testSandboxParsing() throws ParseException, TokeniserException {
        failsToParse("sandbox a!*\n");
        failsToParse("sandbox a!*^:");
        assertEquals("sandbox is valid", "sandbox abc", parse("sandbox abc").getDirectiveByType(SandboxDirective.class).show());
        Policy p;
        p = parse("sandbox a");
        Policy q;
        q = parse("sandbox a");
        SandboxDirective d1 = p.getDirectiveByType(SandboxDirective.class);
        assertTrue("sandbox equals", d1.equals(q.getDirectiveByType(SandboxDirective.class)));
        assertEquals("sandbox hashcode equality", p.hashCode(), q.hashCode());
        q = parse("sandbox b; script-src a");
        assertFalse("sandbox directives equality", d1.equals(q.getDirectiveByType(SandboxDirective.class)));
        d1.union(q.getDirectiveByType(SandboxDirective.class));
        assertEquals("sandbox union", "sandbox a b", d1.show());
        assertNotEquals("sandbox hashcode inequality", p.hashCode(), q.hashCode());
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
    }

    @Test
    public void testHashSource() throws ParseException, TokeniserException {
        failsToParse(
            "script-src 'self' https://example.com 'sha255-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols'");
        failsToParse(
            "script-src 'self' https://example.com 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols'");
        assertEquals("directive-name, directive-value",
            "script-src 'self' https://example.com 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols='",
            parse("script-src 'self' https://example.com 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols='")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value",
            "script-src 'self' https://example.com 'sha384-QXIS/RyLxYlv79jbWK+CRUXoWw0FRkCTZqMK73Jp+uJYFzvRhfsmLIbzu4b7oENo'",
            parse("script-src 'self' https://example.com 'sha384-QXIS/RyLxYlv79jbWK+CRUXoWw0FRkCTZqMK73Jp+uJYFzvRhfsmLIbzu4b7oENo'")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value",
            "script-src 'self' https://example.com 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='",
            parse("script-src 'self' https://example.com 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        Policy p = parse(
            "script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        Policy q = parse("script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertEquals("hash-source hashcode equality", p.hashCode(), q.hashCode());
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("hash-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = parse("script-src 'sha512-HD6Xh+Y6oIZnXv4XqbKxrb6t3RkoPYv+NkqOBE8MwkssuATRE2aFBp8Nm9kp/Xn5a4l2Ki8QkX5qIUlbXQgO4Q=='");
        assertFalse("hash-source inequality",
            d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));

        try {
            parse("script-src 'sha256-gpw4BEAbByf3D3PUQV4WJADL5Xs='");
            fail();
        } catch (ParseException e) {
            assertEquals("Invalid SHA-256 value (wrong length): 20", e.getMessage());
        }

        try {
            parse("script-src 'sha384-gpw4BEAbByf3D3PUQV4WJADL5Xs='");
            fail();
        } catch (ParseException e) {
            assertEquals("Invalid SHA-384 value (wrong length): 20", e.getMessage());
        }

        try {
            parse("script-src 'sha512-gpw4BEAbByf3D3PUQV4WJADL5Xs='");
            fail();
        } catch (ParseException e) {
            assertEquals("Invalid SHA-512 value (wrong length): 20", e.getMessage());
        }
    }

    @Test
    public void sourceListTest() throws ParseException, TokeniserException {
        Policy p = parse("script-src http://a https://b; style-src http://e");
        Policy q = parse("script-src c d");
        ScriptSrcDirective d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        assertFalse("source-list inequality", d1.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        d1.union(q.getDirectiveByType(ScriptSrcDirective.class));
        assertEquals("source-list union", "script-src http://a https://b c d", d1.show());
        ScriptSrcDirective d2 = q.getDirectiveByType(ScriptSrcDirective.class);
        p = parse("script-src http://a https://b");
        q = parse("script-src http://a https://b");
        d1 = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("source-list equality", d1.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        assertEquals("source-list hashcode equality", p.hashCode(), q.hashCode());
    }

    @Test
    public void testNonceSource() throws ParseException, TokeniserException {
        assertEquals("script-src 'self' https://example.com 'nonce-MTIzNDU2Nw=='",
            parse("script-src 'self' https://example.com 'nonce-MTIzNDU2Nw=='")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        Policy p = parse("script-src 'nonce-MTIzNDU2Nw=='");
        Policy q = parse("script-src 'nonce-MTIzNDU2Nw=='");
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertEquals("hash code matches", p.hashCode(), q.hashCode());
        assertTrue("nonce-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = parse("script-src 'nonce-aGVsbG8gd29ybGQ='");
        assertFalse("sandbox !equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
    }

    @Test
    public void testKeywordSource() throws ParseException, TokeniserException {
        assertEquals("directive-name, directive-value", "img-src example.com 'self'",
            parse("img-src example.com 'self'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-inline'",
            parse("img-src example.com 'unsafe-inline'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-eval'",
            parse("img-src example.com 'unsafe-eval'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-redirect'",
            parse("img-src example.com 'unsafe-redirect'").getDirectiveByType(ImgSrcDirective.class).show());
    }


    @Test
    public void testRealData()
        throws FileNotFoundException, ParseException, TokeniserException {
        Scanner sc = new Scanner(this.getClass().getClassLoader().getResourceAsStream("csp.txt"));
        while (sc.hasNextLine()) {
            Policy p;
            String[] line = sc.nextLine().split(":", 2);
            // do not process commented lines
            if (!line[0].startsWith("//")) {
                try {
                    p = parse(line[1]);
                    assertNotNull(String.format("policy should not be null: %s", line[0]), p);
                } catch (ParseException | TokeniserException | IllegalArgumentException e) {
                    System.out.println(line[0]);
                    System.out.println(e);
                }
            }
        }
    }

    @Test
    public void testWarnings() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();
        Policy p1 = Parser.parse("frame-src aaa", "https://origin", warnings);

        assertEquals("frame-src aaa", p1.show());
        assertEquals(1, warnings.size());
        assertEquals("The frame-src directive is deprecated as of CSP version 1.1. Authors who wish to govern nested browsing contexts SHOULD use the child-src directive instead.", warnings.iterator().next().message);
    }

    @Test
    public void testAllowDirective() throws TokeniserException {
        try {
            parse("allow 'none'");
        } catch (ParseException e1) {
            assertEquals("The allow directive has been replaced with default-src and is not in the CSP specification.", e1.getMessage());
            return;
        }
        fail();
    }

    @Test
    public void testOptionsDirective() throws TokeniserException {
        try {
            parse("options inline-script");
        } catch (ParseException e1) {
            assertEquals("The options directive has been replaced with 'unsafe-inline' and 'unsafe-eval' and is not in the CSP specification.", e1.getMessage());
            return;
        }
        fail();
    }

    @Test
    public void testFutureDirectives() throws TokeniserException {
        try {
            parse("referrer no-referrer");
            fail();
        } catch (ParseException e1) {
            assertEquals("The referrer directive is not in the CSP specification yet.", e1.getMessage());
        }

        try {
            parse("upgrade-insecure-requests");
            fail();
        } catch (ParseException e2) {
            assertEquals("The upgrade-insecure-requests directive is not in the CSP specification yet.", e2.getMessage());
        }

        try {
            parse("block-all-mixed-content");
            fail();
        } catch (ParseException e3) {
            assertEquals("The block-all-mixed-content directive is not in the CSP specification yet.", e3.getMessage());
        }

    }

    @Test
    public void testParseMulti() throws ParseException, TokeniserException {
        List<Policy> pl;
        ArrayList<Warning> warnings;

        pl = Parser.parseMulti("script-src a; script-src b, , script-src c; script-src d", "https://origin.com");
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("script-src c", pl.get(1).show());

        pl = Parser.parseMulti("script-src a,", URI.parse("https://origin.com"));
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("", pl.get(1).show());

        warnings = new ArrayList<>();
        pl = Parser.parseMulti("script-src a,", URI.parse("https://origin.com"), warnings);
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("", pl.get(1).show());
        assertEquals(0, warnings.size());

        warnings = new ArrayList<>();
        pl = Parser.parseMulti("script-src a, sandbox", "https://origin.com", warnings);
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("sandbox", pl.get(1).show());
        assertEquals(0, warnings.size());

        warnings = new ArrayList<>();
        pl = ParserWithLocation.parseMulti("   plugin-types  a/b  , script-src 'unsafe-redirect'", "https://origin.com", warnings);
        assertEquals(2, pl.size());
        assertEquals("plugin-types a/b", pl.get(0).show());
        assertEquals("script-src 'unsafe-redirect'", pl.get(1).show());
        assertEquals(1, warnings.size());
        assertEquals("1:36: 'unsafe-redirect' has been removed from CSP as of version 2.0", warnings.get(0).show());

        warnings = new ArrayList<>();
        pl = ParserWithLocation.parseMulti("script-src a, frame-src b",
            URI.parse("https://origin.com"), warnings);
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("frame-src b", pl.get(1).show());
        assertEquals(1, warnings.size());
        assertEquals("1:15: The frame-src directive is deprecated as of CSP version 1.1. Authors who wish to govern nested browsing contexts SHOULD use the child-src directive instead.", warnings.get(0).show());

        try {
            pl.clear();
            pl = Parser.parseMulti("script-src a,b", "https://origin.com");
            fail();
        } catch (IllegalArgumentException e1) {
            assertEquals(0, pl.size());
            assertEquals("Unrecognised directive name: b", e1.getMessage());
        }

        try {
            ParserWithLocation.parse("script-src a, script-src b", "https://origin.com",
                new ArrayList<>());
            fail();
        } catch (ParseException e1) {
            assertEquals(0, pl.size());
            assertEquals("1:13: expecting end of policy but found ,", e1.getMessage());
        }

        try {
            Parser.parse("script-src a, script-src b", "https://origin.com");
            fail();
        } catch (ParseException e1) {
            assertEquals(0, pl.size());
            assertEquals("expecting end of policy but found ,", e1.getMessage());
        }

        try {
            pl.clear();
            pl = ParserWithLocation.parseMulti("allow 'none', options", "https://origin.com");
            fail();
        } catch (ParseException e1) {
            assertEquals(0, pl.size());
            assertEquals("1:1: The allow directive has been replaced with default-src and is not in the CSP specification.", e1.getMessage());
        }

        try {
            pl.clear();
            pl = ParserWithLocation.parseMulti("allow 'none', referrer",
                URI.parse("https://origin.com"));
            fail();
        } catch (ParseException e1) {
            assertEquals(0, pl.size());
            assertEquals("1:1: The allow directive has been replaced with default-src and is not in the CSP specification.", e1.getMessage());
        }

        failsToParse("script-src *, ");
    }

}
