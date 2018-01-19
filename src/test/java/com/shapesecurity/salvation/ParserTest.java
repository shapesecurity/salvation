package com.shapesecurity.salvation;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directives.Directive;
import com.shapesecurity.salvation.directives.FrameAncestorsDirective;
import com.shapesecurity.salvation.directives.ImgSrcDirective;
import com.shapesecurity.salvation.directives.PluginTypesDirective;
import com.shapesecurity.salvation.directives.ReportUriDirective;
import com.shapesecurity.salvation.directives.SandboxDirective;
import com.shapesecurity.salvation.directives.ScriptSrcDirective;
import com.shapesecurity.salvation.tokens.DirectiveNameToken;
import com.shapesecurity.salvation.tokens.DirectiveValueToken;
import com.shapesecurity.salvation.tokens.Token;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ParserTest extends CSPTest {

    @Test public void testEmptyPolicy() {
        Policy p = parse("");
        assertNotNull("empty policy should not be null", p);
    }

    @Test public void testDuplicates() {
        Policy p;
        p = parse("img-src a ;;; img-src b");
        assertNotNull("policy should not be null", p);
        assertEquals("", 1, p.getDirectives().size());
        Directive<?> firstDirective = p.getDirectives().iterator().next();
        ImgSrcDirective imgSrcDirective = p.getDirectiveByType(ImgSrcDirective.class);
        assertNotNull(imgSrcDirective);
        assertTrue(firstDirective instanceof ImgSrcDirective);
        assertEquals("", imgSrcDirective, firstDirective);
        assertEquals("", "img-src", ImgSrcDirective.name);
        assertEquals("", "img-src a", imgSrcDirective.show());
    }

    @Test public void testDuplicatesWithLocation() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = ParserWithLocation.parse("img-src a ;;; img-src b", "https://example.com", notices);
        assertEquals(1, notices.size());
        assertEquals("1:15: Policy contains more than one img-src directive. All but the first instance will be ignored.", notices.get(0).show());

    }

    @Test public void testDirectiveNameParsing() {
        ArrayList<Notice> notices = new ArrayList<>();
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

        p = parse("worker-src a");
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

        p = parse("prefetch-src http://*.example.com:*");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parse("prefetch-src samba://*.example.com");
        assertNotNull("policy should not be null", p);
        assertEquals("directive count", 1, p.getDirectives().size());

        p = parseWithNotices("abc", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Unrecognised directive-name: \"abc\".", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("zzscript-src *; bla", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("Unrecognised directive-name: \"zzscript-src\".", notices.get(0).message);
        assertEquals("Unrecognised directive-name: \"bla\".", notices.get(1).message);
    }

    @Test public void testSourceExpressionParsing() {
        ArrayList<Notice> notices = new ArrayList<>();
        Policy p;
        assertEquals("directive-name, no directive-value", "base-uri", parseAndShow("base-uri"));
        assertEquals("directive-name, <tab>", "base-uri", parseAndShow("base-uri\t"));
        assertEquals("directive-name, <space>", "base-uri", parseAndShow("base-uri "));
        assertEquals("directive-name, 3*<space>", "base-uri", parseAndShow("base-uri   "));
        assertEquals("directive-name, scheme-part", "base-uri https:", parseAndShow("base-uri https:"));
        assertEquals("directive-name, 2*scheme-part", "base-uri file: javascript:",
            parseAndShow("base-uri file: javascript: "));
        assertEquals("directive-name, eliminated scheme-part", "base-uri *", parseAndShow("base-uri * https:"));
        assertEquals("directive-name, host-part *", "base-uri *", parseAndShow("base-uri *"));
        assertEquals("directive-name, host-part *.", "base-uri *.a", parseAndShow("base-uri *.a"));

        assertEquals("represent origin host-source as 'self' keyword-source", "default-src 'self'",
            parse("default-src http://example.com").show());

        p = parseWithNotices("connect-src 'none' scheme:", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("'none' must not be combined with any other source-expression.", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("connect-src scheme: 'none'", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("'none' must not be combined with any other source-expression.", notices.get(0).message);

        // XXX: these two tests are actually valid according to the CSP spec, but we choose not to support paths other than path-abempty
        notices.clear();
        p = parseWithNotices("base-uri abc_", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Expecting source-expression but found \"abc_\".", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("base-uri abc..", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Expecting source-expression but found \"abc..\".", notices.get(0).message);

        assertEquals("directive-name, port-part", "base-uri *:12", parseAndShow("base-uri *:12"));

        notices.clear();
        p = parseWithNotices("base-uri *:ee", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Expecting source-expression but found \"*:ee\".", notices.get(0).message);

        assertEquals("directive-name, path-part", "base-uri */abc", parseAndShow("base-uri */abc"));

        notices.clear();
        p = parseWithNotices("base-uri *\n", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals(
            "Expecting directive-value but found U+000A (\n). Non-ASCII and non-printable characters must be percent-encoded.",
            notices.get(0).message);

        assertEquals("directive-name, full host source", "base-uri https://a.com:888/ert",
            parseAndShow("base-uri https://a.com:888/ert"));

        assertEquals("directive-name, host-source *:*", "script-src *:*", parseAndShow("script-src *:*"));
        assertEquals("directive-name, host-source a:*", "script-src a:*", parseAndShow("script-src a:*"));
        assertEquals("directive-name, host-source http://a:*", "script-src http://a:*",
            parseAndShow("script-src http://a:*"));

        assertEquals("optimisation", "script-src *", parseAndShow("script-src example.com *"));
        assertEquals("optimisation", "script-src *", parseAndShow("script-src 'self' *"));
        assertEquals("optimisation", "script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            parseAndShow("script-src 'unsafe-inline'; style-src 'unsafe-inline';"));
        assertEquals("optimisation with network scheme", "script-src *", parseAndShow("script-src 'self' * ftp:"));
        assertEquals("optimisation with other scheme", "script-src data: *", parseAndShow("script-src 'self' * data:"));
        assertEquals("optimisation with other scheme", "script-src custom: *", parseAndShow("script-src 'self' * custom:"));
        assertEquals("optimisation with mixed schemes", "script-src custom: blob: *", parseAndShow("script-src 'self' * custom: ftp: blob:"));
        assertEquals("optimisation", "script-src 'unsafe-inline' *", parseAndShow("script-src example.com * 'unsafe-inline'"));
        assertEquals("optimisation", "script-src 'nonce-123' *", parseAndShow("script-src example.com * 'unsafe-inline' 'nonce-123'"));
        assertEquals("optimisation", "script-src 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=' *", parseAndShow("script-src example.com * 'unsafe-inline' 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols='"));
        assertEquals("optimisation", "script-src 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=' 'nonce-123' *", parseAndShow("script-src example.com * 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=' 'nonce-123' 'unsafe-inline'"));

        p = parse("script-src a; style-src a; img-src a; child-src a; connect-src a; font-src a; media-src a; object-src a; manifest-src a ");
        assertEquals("script-src a; style-src a; img-src a; child-src a; connect-src a; font-src a; media-src a; object-src a; manifest-src a", p.show());
        p = parse("form-action a; script-src a; style-src a; img-src a; child-src a; connect-src a; font-src a; media-src a; object-src a; manifest-src a ");
        assertEquals("form-action a; script-src a; style-src a; img-src a; child-src a; connect-src a; font-src a; media-src a; object-src a; manifest-src a", p.show());
        p = parse("script-src 'nonce-1234'; style-src 'nonce-1234'");
        assertEquals("script-src 'nonce-1234'; style-src 'nonce-1234'", p.show());
        p = parse("script-src 'nonce-abcd'; style-src 'nonce-1234'");
        assertEquals("script-src 'nonce-abcd'; style-src 'nonce-1234'", p.show());
        p = parse("script-src 'nonce-abcd' 'nonce-1234'; style-src 'nonce-1234'");
        assertEquals("script-src 'nonce-abcd' 'nonce-1234'; style-src 'nonce-1234'", p.show());
        p = parse("script-src a 'nonce-1234'; style-src a 'nonce-1234'");
        assertEquals("script-src a 'nonce-1234'; style-src a 'nonce-1234'", p.show());
        p = parse("script-src 'nonce-1234'; style-src 'nonce-1234'; default-src a");
        assertEquals("script-src 'nonce-1234'; style-src 'nonce-1234'; default-src a", p.show());

        p = parse("script-src http://example.org/cpproducts/index.htm;jsessionid=0C159CF2854B7519C5379634FAC36577");
        assertEquals("script-src http://example.org/cpproducts/index.htm", p.show());

        p = parse("script-src http://example.org/cpproducts/index.htm%3Bjsessionid=0C159CF2854B7519C5379634FAC36577");
        assertEquals("script-src http://example.org/cpproducts/index.htm%3Bjsessionid=0C159CF2854B7519C5379634FAC36577", p.show());

        p = parse("script-src http://example.org/cpproducts/index.htm,jsessionid=0C159CF2854B7519C5379634FAC36577");
        assertEquals("script-src http://example.org/cpproducts/index.htm", p.show());

        p = parse("script-src http://example.org/cpproducts/index.htm%2Cjsessionid=0C159CF2854B7519C5379634FAC36577");
        assertEquals("script-src http://example.org/cpproducts/index.htm%2Cjsessionid=0C159CF2854B7519C5379634FAC36577", p.show());

    }

    @Test public void testAncestorSource() {
        ArrayList<Notice> notices = new ArrayList<>();
        assertEquals("directive-name, no directive-value", "frame-ancestors",
            parse("frame-ancestors").getDirectiveByType(FrameAncestorsDirective.class).show());
        assertEquals("directive-name, directive-value", "frame-ancestors 'none'",
            parse("frame-ancestors  'none'").getDirectiveByType(FrameAncestorsDirective.class).show());

        Policy p;
        p = parse("frame-ancestors 'self'       https://example.com");
        Policy q;
        q = parse("script-src abc; frame-ancestors http://example.com");
        FrameAncestorsDirective d1 = p.getDirectiveByType(FrameAncestorsDirective.class);
        FrameAncestorsDirective d2 = q.getDirectiveByType(FrameAncestorsDirective.class);

        d1.union(d2);
        assertEquals("ancestor-source union", "frame-ancestors 'self' https://example.com http://example.com",
            d1.show());
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

        q = parse("frame-ancestors 'self'");
        p = parse("frame-ancestors 'SELF'");
        assertTrue("ancestor-source scheme-source equality", p.equals(q));

        p = parseWithNotices("frame-ancestors scheme::", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Expecting ancestor-source but found \"scheme::\".", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("frame-ancestors 'none' 'self'", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("'none' must not be combined with any other ancestor-source.", notices.get(0).message);

        p = parse("frame-ancestors *    ");
        q = parse("frame-ancestors http://example.com");
        p.union(q);
        assertEquals("frame-ancestors *", p.show());
    }

    @Test public void testPolicy() {
        Policy a = parse("");
        assertEquals("policy show", "", a.show());

        Policy b = parse("style-src *");
        assertEquals("policy show", "style-src *", b.show());

        assertFalse("policy equality", a.equals(b));

        a = parse("style-src 'self' *");
        assertEquals("policy show", "style-src *", a.show());

        b = parse("style-src *");
        assertEquals("policy show", "style-src *", b.show());

        assertTrue("policy equality", a.equals(b));

        Policy c = parse("script-src *");
        b.union(c);
        assertEquals("policy union", "style-src *; script-src *", b.show());

        Policy d = parse("script-src abc");
        b.union(d);
        assertEquals("policy union", "style-src *; script-src *", b.show());

        a.setOrigin(URI.parse("http://qwe.zz:80"));
        assertEquals("policy origin", "http://qwe.zz", a.getOrigin().show());
    }

    @Test() public void testPluginTypesParsing() {
        ArrayList<Notice> notices = new ArrayList<>();

        parseWithNotices("plugin-types", notices);
        assertEquals(1, notices.size());
        assertEquals("The media-type-list must contain at least one media-type.", notices.get(0).message);

        notices.clear();
        parseWithNotices("plugin-types */* a/a", notices);
        assertEquals(1, notices.size());
        assertEquals("Media types can only be matched literally. Make sure using `*` is not an oversight.", notices.get(0).message);

        notices.clear();
        // XXX: technically allowed via ietf-token if an RFC introduces a type/subtype that is empty
        parseWithNotices("plugin-types /", notices);
        assertEquals(1, notices.size());
        assertEquals("Expecting media-type but found \"/\".", notices.get(0).message);

        assertEquals("directive-name, directive-value", "plugin-types a/b",
            parse("plugin-types a/b").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d",
            parse("plugin-types a/b c/d").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types x-a/x-b",
            parse("plugin-types x-a/x-b").getDirectiveByType(PluginTypesDirective.class).show());
        assertEquals("directive-name, directive-value", "plugin-types X-A/X-B",
            parse("plugin-types X-A/X-B").getDirectiveByType(PluginTypesDirective.class).show());

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

    @Test public void testReportUri() {
        ArrayList<Notice> notices = new ArrayList<>();

        parseWithNotices("report-uri ", notices);
        assertEquals(2, notices.size());
        assertEquals("A draft of the next version of CSP deprecates report-uri in favour of a new report-to directive.", notices.get(0).message);
        assertEquals("The report-uri directive must contain at least one uri-reference.", notices.get(1).message);

        notices.clear();
        parseWithNotices("report-uri #\"", notices);
        assertEquals(2, notices.size());
        assertEquals("A draft of the next version of CSP deprecates report-uri in favour of a new report-to directive.", notices.get(0).message);
        assertEquals("Expecting uri-reference but found \"#\"\".", notices.get(1).message);

        notices.clear();
        parseWithNotices("report-uri a", notices);
        assertEquals(2, notices.size());
        assertEquals("Expecting uri-reference but found \"a\".", notices.get(1).message);

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

    @Test public void testReportTo() {
        ArrayList<Notice> notices = new ArrayList<>();

        parseWithNotices("report-to ", notices);
        assertEquals(1, notices.size());
        assertEquals("The report-to directive must contain exactly one RFC 7230 token.", notices.get(0).message);

        notices.clear();
        parseWithNotices("report-to д", notices);
        assertEquals(2, notices.size());
        assertEquals("The report-to directive must contain exactly one RFC 7230 token.", notices.get(0).message);
        assertEquals("Expecting directive-value but found U+0434 (д). Non-ASCII and non-printable characters must be percent-encoded.", notices.get(1).message);

        notices.clear();
        parseWithNotices("report-to a b", notices);
        assertEquals(1, notices.size());
        assertEquals("Expecting RFC 7230 token but found \"a b\".", notices.get(0).message);

        Policy p, q;
        p = parse("report-to a");
        q = parse("report-to b");
        assertNotEquals("report-to hashcode shouldn't match", p.hashCode(), q.hashCode());

        p = parse("report-to        a");
        q = parse("report-to a; ");
        assertFalse("report-to equals", p.equals(q));
    }

    @Test public void testMediaTypeUnion() {
        Policy p;
        p = parse("plugin-types a/b");
        Policy q;
        q = parse("plugin-types c/d");
        PluginTypesDirective d1 = p.getDirectiveByType(PluginTypesDirective.class);
        PluginTypesDirective d2 = q.getDirectiveByType(PluginTypesDirective.class);
        d1.union(d2);
        assertEquals("directive-name, directive-value", "plugin-types a/b c/d", d1.show());
    }

    @Test public void testSandboxParsing() {
        ArrayList<Notice> notices = new ArrayList();
        Policy p;
        p = parseWithNotices("sandbox allow-forms", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

        notices.clear();
        p = parseWithNotices("sandbox allow-forms       allow-popups", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals("sandbox allow-forms allow-popups", p.show());
        assertEquals(0, notices.size());

        notices.clear();
        p = parseWithNotices("sandbox allow-forms allow-forms       ", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals("sandbox allow-forms", p.show());
        assertEquals(0, notices.size());

        notices.clear();
        p = parseWithNotices("sandbox allow-forms allow_forms", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals("sandbox allow-forms allow_forms", p.show());
        assertEquals(1, notices.size());
        assertEquals(
            "The sandbox directive should contain only allow-forms, allow-modals, allow-pointer-lock, allow-popups, allow-popups-to-escape-sandbox, allow-same-origin, allow-scripts, or allow-top-navigation.",
            notices.get(0).message);

        notices.clear();
        p = parseWithNotices("sandbox a!*\n", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals(
            "The sandbox directive should contain only allow-forms, allow-modals, allow-pointer-lock, allow-popups, allow-popups-to-escape-sandbox, allow-same-origin, allow-scripts, or allow-top-navigation.",
            notices.get(0).message);
        assertEquals("Expecting directive-value but found U+000A (\n"
            + "). Non-ASCII and non-printable characters must be percent-encoded.", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("sandbox a!*^:", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals(
            "The sandbox directive should contain only allow-forms, allow-modals, allow-pointer-lock, allow-popups, allow-popups-to-escape-sandbox, allow-same-origin, allow-scripts, or allow-top-navigation.",
            notices.get(0).message);
        assertEquals("Expecting RFC 7230 token but found \"a!*^:\".", notices.get(1).message);

        assertEquals("sandbox is valid", "sandbox abc",
            parse("sandbox abc").getDirectiveByType(SandboxDirective.class).show());

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

    @Test public void testHashSource() {
        ArrayList<Notice> notices = new ArrayList();
        Policy p;
        p = parseWithNotices(
            "script-src 'self' https://example.com 'sha255-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols'", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Unrecognised hash algorithm: \"sha255\".", notices.get(0).message);

        notices.clear();
        p = parseWithNotices(
            "script-src 'self' https://example.com 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols'", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals(
            "Invalid base64-value (should be multiple of 4 bytes: 43).",
            notices.get(0).message);

        assertEquals("directive-name, directive-value",
            "script-src 'self' https://example.com 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols='",
            parse("script-src 'self' https://example.com 'sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols='")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value",
            "script-src 'self' https://example.com 'sha384-QXIS/RyLxYlv79jbWK+CRUXoWw0FRkCTZqMK73Jp+uJYFzvRhfsmLIbzu4b7oENo'",
            parse(
                "script-src 'self' https://example.com 'sha384-QXIS/RyLxYlv79jbWK+CRUXoWw0FRkCTZqMK73Jp+uJYFzvRhfsmLIbzu4b7oENo'")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals("directive-name, directive-value",
            "script-src 'self' https://example.com 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='",
            parse(
                "script-src 'self' https://example.com 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='")
                .getDirectiveByType(ScriptSrcDirective.class).show());
        p = parse(
            "script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        Policy q = parse(
            "script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
        assertEquals("hash-source hashcode equality", p.hashCode(), q.hashCode());
        ScriptSrcDirective d = p.getDirectiveByType(ScriptSrcDirective.class);
        assertTrue("hash-source equals", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));
        q = parse(
            "script-src 'sha512-HD6Xh+Y6oIZnXv4XqbKxrb6t3RkoPYv+NkqOBE8MwkssuATRE2aFBp8Nm9kp/Xn5a4l2Ki8QkX5qIUlbXQgO4Q=='");
        assertFalse("hash-source inequality", d.equals(q.getDirectiveByType(ScriptSrcDirective.class)));

        notices.clear();
        parseWithNotices("script-src 'sha256-gpw4BEAbByf3D3PUQV4WJADL5Xs='", notices);

        assertEquals("Error", notices.get(0).type.getValue());
        assertEquals("Invalid SHA-256 value (wrong length): 20.", notices.get(0).message);

        notices.clear();
        parseWithNotices("script-src 'sha384-gpw4BEAbByf3D3PUQV4WJADL5Xs='", notices);
        assertEquals("Error", notices.get(0).type.getValue());
        assertEquals("Invalid SHA-384 value (wrong length): 20.", notices.get(0).message);

        notices.clear();
        parseWithNotices("script-src 'sha512-gpw4BEAbByf3D3PUQV4WJADL5Xs='", notices);
        assertEquals("Error", notices.get(0).type.getValue());
        assertEquals("Invalid SHA-512 value (wrong length): 20.", notices.get(0).message);
    }

    @Test public void sourceListTest() {
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

    @Test public void testNonceSource() {
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

    @Test public void testKeywordSource() {
        assertEquals("directive-name, directive-value", "img-src example.com 'self'",
            parse("img-src example.com 'self'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-inline'",
            parse("img-src example.com 'unsafe-inline'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-eval'",
            parse("img-src example.com 'unsafe-eval'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src example.com 'unsafe-redirect'",
            parse("img-src example.com 'unsafe-redirect'").getDirectiveByType(ImgSrcDirective.class).show());
        assertEquals("directive-name, directive-value", "img-src 'nonce-123' 'strict-dynamic'",
            parse("img-src 'nonce-123' 'strict-dynamic'").getDirectiveByType(ImgSrcDirective.class).show());
    }

    @Test public void testDirectNameSpacing() {
        ArrayList<Notice> notices = new ArrayList<>();
        Policy p = parseWithNotices("script-src'self'", notices);

        assertEquals("", p.show());
        assertEquals(1, notices.size());
        assertEquals(Notice.Type.ERROR, notices.get(0).type);
        assertEquals("Expecting directive-value but found U+0027 ('). Non-ASCII and non-printable characters must be percent-encoded.", notices.get(0).message);
    }

    @Test public void testDirectValueSpacing() {
        Token[] tokens = Tokeniser.tokenise("some-directive-name   a  ");

        assertEquals(2, tokens.length);
        assertTrue(tokens[0] instanceof DirectiveNameToken);
        assertEquals("some-directive-name", tokens[0].value);
        assertEquals(DirectiveNameToken.DirectiveNameSubtype.Unrecognised, ((DirectiveNameToken) tokens[0]).subtype);
        assertTrue(tokens[1] instanceof DirectiveValueToken);
        assertEquals("  a  ", tokens[1].value);
    }

    @Test public void testUnknownTokens() {
        ArrayList<Notice> notices = new ArrayList();
        Policy p = parseWithNotices("img-src √", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals(
            "Expecting directive-value but found U+221A (√). Non-ASCII and non-printable characters must be percent-encoded.",
            notices.get(0).message);

        notices.clear();
        p = parseWithNotices("img-src √; img-src a", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals(
            "Expecting directive-value but found U+221A (√). Non-ASCII and non-printable characters must be percent-encoded.",
            notices.get(0).message);

        notices.clear();
        p = parseWithNotices("√ a b c; img-src a", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Expecting directive-name but found \"√\".", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("script-src 𝌆", notices); // non-ASCII char in source-expression
        assertEquals(0, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals(
            "Expecting directive-value but found U+1D306 (𝌆). Non-ASCII and non-printable characters must be percent-encoded.",
            notices.get(0).message);

        notices.clear();
        p = parseWithNotices("plugin-types х/п", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("The media-type-list must contain at least one media-type.", notices.get(0).message);
        assertEquals(
            "Expecting directive-value but found U+0445 (х). Non-ASCII and non-printable characters must be percent-encoded.",
            notices.get(1).message);

    }


    @Test public void testRealData() throws FileNotFoundException {
        Scanner sc = new Scanner(this.getClass().getClassLoader().getResourceAsStream("csp.txt"));
        while (sc.hasNextLine()) {
            Policy p;
            String[] line = sc.nextLine().split(":", 2);
            // do not process commented lines
            if (!line[0].startsWith("//")) {
                try {
                    ArrayList<Notice> n = new ArrayList<>();
                    p = parseWithNotices(line[1], n);
                    assertNotNull(String.format("policy should not be null: %s", line[0]), p);
                } catch (IllegalArgumentException e) {
                    System.out.println(line[0]);
                    System.out.println(e);
                    fail();
                }
            }
        }
    }

    @Test public void testWarnings() {
        ArrayList<Notice> notices = new ArrayList<>();
        Policy p1 = Parser.parse("child-src aaa", "https://origin", notices);

        assertEquals("child-src aaa", p1.show());
        assertEquals(1, notices.size());
        assertEquals(
            "The child-src directive is deprecated as of CSP level 3. Authors who wish to regulate nested browsing contexts and workers SHOULD use the frame-src and worker-src directives, respectively.",
            notices.iterator().next().message);
    }

    @Test public void testAllowDirective() {
        ArrayList<Notice> notices = new ArrayList<>();
        parseWithNotices("allow 'none'", notices);
        assertEquals("Error", notices.get(0).type.getValue());
        assertEquals("The allow directive has been replaced with default-src and is not in the CSP specification.",
            notices.get(0).message);

    }

    @Test public void testOptionsDirective() {
        ArrayList<Notice> notices = new ArrayList<>();
        parseWithNotices("options inline-script", notices);
        assertEquals("Error", notices.get(0).type.getValue());
        assertEquals(
            "The options directive has been replaced with 'unsafe-inline' and 'unsafe-eval' and is not in the CSP specification.",
            notices.get(0).message);
    }

    @Test public void testNewDirectives() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = parseWithNotices("referrer no-referrer", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());

        notices.clear();
        p = parseWithNotices("referrer", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("The referrer directive was an experimental directive that was proposed but never added to the CSP specification. Support for this directive will be removed. See Referrer Policy specification.", notices.get(0).message);
        assertEquals("The referrer directive must contain exactly one referrer directive value.", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("referrer   no-referrer  ", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("Expecting referrer directive value but found \"  no-referrer  \".", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("referrer aaa", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("Expecting referrer directive value but found \"aaa\".", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("referrer no-referrer unsafe-url", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("Expecting referrer directive value but found \"no-referrer unsafe-url\".", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("upgrade-insecure-requests", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());

        notices.clear();
        p = parseWithNotices("upgrade-insecure-requests a", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("The upgrade-insecure-requests directive is an experimental directive that will be likely added to the CSP specification.", notices.get(0).message);
        assertEquals("The upgrade-insecure-requests directive must not contain any value.", notices.get(1).message);


        notices.clear();
        p = parseWithNotices("block-all-mixed-content", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());

        notices.clear();
        p = parseWithNotices("block-all-mixed-content a a", notices);
        assertEquals(0, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("The block-all-mixed-content directive must not contain any value.", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("require-sri-for", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Empty require-sri-for directive has no effect.", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("require-sri-for script", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
        assertEquals("require-sri-for script", p.show());

        notices.clear();
        p = parseWithNotices("require-sri-for style", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
        assertEquals("require-sri-for style", p.show());

        notices.clear();
        p = parseWithNotices("require-sri-for script    style", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
        assertEquals("require-sri-for script style", p.show());

        notices.clear();
        p = parseWithNotices("require-sri-for Script    StYlE", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
        assertEquals("require-sri-for script style", p.show());

        notices.clear();
        p = parseWithNotices("require-sri-for script script", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isWarning());
        assertEquals("The require-sri-for directive contains duplicate token: \"script\".", notices.get(0).message);
        assertEquals("require-sri-for script", p.show());

        notices.clear();
        p = parseWithNotices("require-sri-for Script sCrIpT", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isWarning());
        assertEquals("The require-sri-for directive contains duplicate token: \"script\".", notices.get(0).message);
        assertEquals("require-sri-for script", p.show());

        notices.clear();
        p = parseWithNotices("require-sri-for script bla script", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertTrue(notices.get(0).isWarning());
        assertTrue(notices.get(1).isWarning());
        assertEquals("The require-sri-for directive should contain only \"script\", \"style\" tokens.", notices.get(0).message);
        assertEquals("The require-sri-for directive contains duplicate token: \"script\".", notices.get(1).message);
        assertEquals("require-sri-for script bla", p.show());
    }

    @Test public void testStrictDynamic() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = parseWithNotices("script-src a 'strict-dynamic'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isInfo());
        assertEquals("The host-source and scheme-source expressions, as well as the \"'unsafe-inline'\" and \"'self'\" keyword-sources have no effect in source lists that contain \"'strict-dynamic'\" in CSP3 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);
        assertEquals("script-src a 'strict-dynamic'", p.show());

        notices.clear();
        p = parseWithNotices("script-src 'strict-dynamic' a", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isInfo());
        assertEquals("The host-source and scheme-source expressions, as well as the \"'unsafe-inline'\" and \"'self'\" keyword-sources have no effect in source lists that contain \"'strict-dynamic'\" in CSP3 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);
        assertEquals("script-src 'strict-dynamic' a", p.show());

        notices.clear();
        p = parseWithNotices("script-src 'strict-dynamic' https:", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isInfo());
        assertEquals("The host-source and scheme-source expressions, as well as the \"'unsafe-inline'\" and \"'self'\" keyword-sources have no effect in source lists that contain \"'strict-dynamic'\" in CSP3 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);
        assertEquals("script-src 'strict-dynamic' https:", p.show());

        notices.clear();
        p = parseWithNotices("script-src 'strict-dynamic' 'self'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isInfo());
        assertEquals("The host-source and scheme-source expressions, as well as the \"'unsafe-inline'\" and \"'self'\" keyword-sources have no effect in source lists that contain \"'strict-dynamic'\" in CSP3 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);
        assertEquals("script-src 'strict-dynamic' 'self'", p.show());

        notices.clear();
        p = parseWithNotices("script-src 'strict-dynamic' 'unsafe-inline'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).isInfo());
        assertEquals("The host-source and scheme-source expressions, as well as the \"'unsafe-inline'\" and \"'self'\" keyword-sources have no effect in source lists that contain \"'strict-dynamic'\" in CSP3 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);
        assertEquals("script-src 'strict-dynamic' 'unsafe-inline'", p.show());

        notices.clear();
        p = parseWithNotices("script-src 'strict-dynamic' 'unsafe-inline' 'self' a https:", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(4, notices.size());
        assertTrue(notices.get(0).isInfo());
        assertEquals("The host-source and scheme-source expressions, as well as the \"'unsafe-inline'\" and \"'self'\" keyword-sources have no effect in source lists that contain \"'strict-dynamic'\" in CSP3 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);
        assertEquals("script-src 'strict-dynamic' 'unsafe-inline' 'self' a https:", p.show());

        notices.clear();
        p = parseWithNotices("script-src 'strict-dynamic' 'unsafe-eval'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
        assertEquals("script-src 'strict-dynamic' 'unsafe-eval'", p.show());
    }

    @Test public void testParseMulti() {
        List<Policy> pl;
        ArrayList<Notice> notices;

        pl = Parser.parseMulti("script-src a; script-src b, , script-src c; script-src d", "https://origin.com");
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("script-src c", pl.get(1).show());

        pl = Parser.parseMulti("script-src a,", URI.parse("https://origin.com"));
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("", pl.get(1).show());

        notices = new ArrayList<>();
        pl = Parser.parseMulti("script-src a,", URI.parse("https://origin.com"), notices);
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("", pl.get(1).show());
        assertEquals(0, notices.size());

        notices = new ArrayList<>();
        pl = Parser.parseMulti("script-src a, sandbox", "https://origin.com", notices);
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("sandbox", pl.get(1).show());
        assertEquals(0, notices.size());

        notices = new ArrayList<>();
        pl = ParserWithLocation
            .parseMulti("   plugin-types  a/b  , script-src 'unsafe-redirect'", "https://origin.com", notices);
        assertEquals(2, pl.size());
        assertEquals("plugin-types a/b", pl.get(0).show());
        assertEquals("script-src 'unsafe-redirect'", pl.get(1).show());
        assertEquals(1, notices.size());
        assertEquals("1:36: 'unsafe-redirect' has been removed from CSP as of version 2.0.", notices.get(0).show());

        notices = new ArrayList<>();
        pl = ParserWithLocation.parseMulti("script-src a, child-src b", URI.parse("https://origin.com"), notices);
        assertEquals(2, pl.size());
        assertEquals("script-src a", pl.get(0).show());
        assertEquals("child-src b", pl.get(1).show());
        assertEquals(1, notices.size());
        assertEquals(
            "1:15: The child-src directive is deprecated as of CSP level 3. Authors who wish to regulate nested browsing contexts and workers SHOULD use the frame-src and worker-src directives, respectively.",
            notices.get(0).show());

        pl.clear();
        notices.clear();
        pl = parseMultiWithNotices("script-src a,b", notices);
        assertEquals(2, pl.size());
        assertEquals("Unrecognised directive-name: \"b\".", notices.get(0).message);

        notices.clear();
        Policy p;
        p = ParserWithLocation.parse("script-src a, script-src b", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals("1:13: Expecting end of policy but found \",\".", notices.get(0).show());

        notices.clear();
        p = parseWithNotices("script-src a, script-src b", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals("Expecting end of policy but found \",\".", notices.get(0).message);

        notices.clear();
        pl.clear();
        pl = ParserWithLocation.parseMulti("allow 'none', options", "https://origin.com", notices);
        assertEquals(2, pl.size());
        assertEquals(2, notices.size());
        assertEquals("1:1: The allow directive has been replaced with default-src and is not in the CSP specification.",
            notices.get(0).show());
        assertEquals(
            "1:15: The options directive has been replaced with 'unsafe-inline' and 'unsafe-eval' and is not in the CSP specification.",
            notices.get(1).show());


        notices.clear();
        pl.clear();
        pl = ParserWithLocation.parseMulti("allow 'none', referrer", URI.parse("https://origin.com"), notices);
        assertEquals(2, pl.size());
        assertEquals(3, notices.size());
        assertEquals("1:1: The allow directive has been replaced with default-src and is not in the CSP specification.",
            notices.get(0).show());
        assertEquals("1:15: The referrer directive was an experimental directive that was proposed but never added to the CSP specification. Support for this directive will be removed. See Referrer Policy specification.", notices.get(1).show());
        assertEquals("1:15: The referrer directive must contain exactly one referrer directive value.", notices.get(2).show());

        notices.clear();
        p = parseWithNotices("script-src *, ", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("Expecting end of policy but found \",\".", notices.get(0).message);
    }

    @Test public void testUnsafeInlineWithHashNonce() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = parseWithNotices("default-src 'unsafe-inline' 'nonce-abcdef'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("The \"'unsafe-inline'\" keyword-source has no effect in source lists that contain hash-source or nonce-source in CSP2 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("default-src 'Unsafe-INLINE' 'nonce-abcd'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("The \"'unsafe-inline'\" keyword-source has no effect in source lists that contain hash-source or nonce-source in CSP2 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-inline' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("The \"'unsafe-inline'\" keyword-source has no effect in source lists that contain hash-source or nonce-source in CSP2 and later. Ensure that this pattern is only used for backwards compatibility with older CSP implementations and is not an oversight.", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-inline' 'unsafe-redirect'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("'unsafe-redirect' has been removed from CSP as of version 2.0.", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-inline'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
    }

    @Test public void testUnsafeHashedAttributes() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = parseWithNotices("default-src 'unsafe-hashed-attributes' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-hashed-attributes'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("The \"'unsafe-hashed-attributes'\" keyword-source has no effect in source lists that do not contain hash-source in CSP3 and later.", notices.get(0).message);

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-hashed-attributes' 'unsafe-hashed-attributes' 'unsafe-hashed-attributes'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(3, notices.size());
        assertEquals("Source list contains duplicate source expression \"'unsafe-hashed-attributes'\". All but the first instance will be ignored.", notices.get(0).message);
        assertEquals("Source list contains duplicate source expression \"'unsafe-hashed-attributes'\". All but the first instance will be ignored.", notices.get(1).message);
        assertEquals("The \"'unsafe-hashed-attributes'\" keyword-source has no effect in source lists that do not contain hash-source in CSP3 and later.", notices.get(2).message);

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-hashed-attributes' 'unsafe-hashed-attributes' 'unsafe-hashed-attributes' 'nonce-123'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(4, notices.size());
        assertEquals("Source list contains duplicate source expression \"'unsafe-hashed-attributes'\". All but the first instance will be ignored.", notices.get(0).message);
        assertEquals("Source list contains duplicate source expression \"'unsafe-hashed-attributes'\". All but the first instance will be ignored.", notices.get(1).message);
        assertEquals("Invalid base64-value (should be multiple of 4 bytes: 3).", notices.get(2).message);
        assertEquals("The \"'unsafe-hashed-attributes'\" keyword-source has no effect in source lists that do not contain hash-source in CSP3 and later.", notices.get(3).message);

        notices.clear();
        p = parseWithNotices("default-src 'unsafe-hashed-attributes' 'unsafe-hashed-attributes' 'unsafe-hashed-attributes' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("Source list contains duplicate source expression \"'unsafe-hashed-attributes'\". All but the first instance will be ignored.", notices.get(0).message);
        assertEquals("Source list contains duplicate source expression \"'unsafe-hashed-attributes'\". All but the first instance will be ignored.", notices.get(1).message);

        notices.clear();
        p = parseWithNotices("default-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

        // while grammar allows this, I am open to throw warnings about directives that don't make sense with 'usnafe-hashed-attributes'
        notices.clear();
        p = parseWithNotices("img-src 'unsafe-hashed-attributes' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
    }

    @Test public void testReportSample() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = parseWithNotices("default-src 'report-sample'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

        notices.clear();
        p = parseWithNotices("script-src 'report-sample' 'report-sample'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals("script-src 'report-sample'", p.getDirectiveByType(ScriptSrcDirective.class).show());
        assertEquals(1, notices.size());
        assertEquals("Source list contains duplicate source expression \"'report-sample'\". All but the first instance will be ignored.", notices.get(0).show());

        notices.clear();
        p = parseWithNotices("default-src 'strict-dynamic' 'report-sample'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

        notices.clear();
        p = parseWithNotices("img-src 'report-sample'", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());
    }

    @Test public void testDuplicateSourceExpressions() {
        Policy p;
        ArrayList<Notice> notices = new ArrayList<>();
        p = ParserWithLocation.parse("script-src 'unsafe-inline' 'unsafe-inline'", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("1:28: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(0).show());

        notices.clear();
        p = ParserWithLocation.parse("script-src 'unsafe-inline' 'unsafe-inline' 'unsafe-inline'", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("1:28: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(0).show());
        assertEquals("1:44: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(1).show());

        notices.clear();
        p = ParserWithLocation.parse("script-src 'unsafe-inline' a b 'unsafe-INLINE' 'unsafe-inline';", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("1:32: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(0).show());
        assertEquals("1:48: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(1).show());

        notices.clear();
        p = ParserWithLocation.parse("script-src 'unsafe-inline' a 'unsafe-INLINE'; style-src 'unsafe-inline' 'unsafe-INLINE' b;", "https://origin.com", notices);
        assertEquals(2, p.getDirectives().size());
        assertEquals(2, notices.size());
        assertEquals("1:30: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(0).show());
        assertEquals("1:73: Source list contains duplicate source expression \"'unsafe-inline'\". All but the first instance will be ignored.", notices.get(1).show());


        notices.clear();
        p = ParserWithLocation.parse("script-src a A ;", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(1, notices.size());
        assertEquals("1:14: Source list contains duplicate source expression \"A\". All but the first instance will be ignored.", notices.get(0).show());

        notices.clear();
        p = ParserWithLocation.parse("script-src http: HTTP: ;", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

        notices.clear();
        p = ParserWithLocation.parse("script-src http://example.com/a http://example.com/A ;", "https://origin.com", notices);
        assertEquals(1, p.getDirectives().size());
        assertEquals(0, notices.size());

    }
}
