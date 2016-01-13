package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.HostSource;
import com.shapesecurity.salvation.directiveValues.NonceSource;
import com.shapesecurity.salvation.directiveValues.SourceExpression;
import com.shapesecurity.salvation.directives.DefaultSrcDirective;
import com.shapesecurity.salvation.directives.ScriptSrcDirective;
import com.shapesecurity.salvation.directives.StyleSrcDirective;
import org.junit.Test;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class PolicyMergeTest extends CSPTest {

    @Test public void testUnion() {
        Policy p1, p2;

        p1 = Parser.parse("default-src aaa", "https://origin1.com");
        p2 = Parser.parse("default-src 'self'", "https://origin2.com");
        p1.union(p2);
        assertEquals("default-src aaa https://origin2.com", p1.show());

        p1 = Parser.parse("default-src d; connect-src a; script-src a; media-src a", "https://origin1.com");
        p2 = Parser.parse("default-src; img-src b; style-src b; font-src b; child-src b; object-src b", "https://origin2.com");
        p1.union(p2);
        assertEquals("connect-src a; script-src a; media-src a; style-src d b; img-src d b; child-src d b; font-src d b; object-src d b", p1.show());
    }

    @Test public void testUnionDefaultSrc() {
        Policy p1, p2;

        p1 = parse("default-src a b");
        p2 = parse("default-src; script-src x; style-src y");
        p1.union(p2);
        assertEquals("default-src a b; script-src a b x; style-src a b y", p1.show());

        p1 = parse("default-src *; script-src");
        p2 = parse("default-src; script-src b");
        p1.union(p2);
        assertEquals("script-src b", p1.show());

        p1 = parse("default-src a");
        p2 = parse("default-src; script-src b");
        p1.union(p2);
        assertEquals("default-src a; script-src a b", p1.show());

        p1 = parse("default-src a; script-src b");
        p2 = parse("default-src; script-src c");
        p1.union(p2);
        assertEquals("default-src a; script-src b c", p1.show());

        p1 = parse("default-src; img-src a; script-src b");
        p2 = parse("default-src c");
        p1.union(p2);
        assertEquals("default-src c; img-src a c; script-src b c", p1.show());

        p1 = parse("default-src 'nonce-VJKP7yRkG1Ih3BqNrUN7'; script-src a");
        p2 = parse("default-src; style-src b");
        p1.union(p2);
        assertEquals("default-src; script-src a; style-src 'nonce-VJKP7yRkG1Ih3BqNrUN7' b", p1.show());

        p1 = parse("default-src a; script-src b");
        p2 = parse("default-src c; img-src d");
        p1.union(p2);
        assertEquals("default-src a c; script-src b c; img-src a d", p1.show());

        p1 = parse("default-src b; script-src a");
        p2 = parse("default-src a");
        p1.union(p2);
        assertEquals("default-src b a; script-src a", p1.show());
    }

    @Test public void testIntersect() {
        Policy  p1, p2;

        p1 = parse("default-src a; script-src b");
        p2 = parse("default-src c; img-src d");
        p1.intersect(p2);
        assertEquals("default-src", p1.show());

        p1 = parse("default-src a b");
        p2 = parse("script-src x; style-src y");
        p1.intersect(p2);
        assertEquals("default-src a b; script-src; style-src", p1.show());

        p1 = parse("default-src 'none'");
        p2 = parse("script-src x; style-src y");
        p1.intersect(p2);
        assertEquals("default-src", p1.show());

        p1 = parse("script-src a");
        p2 = parse("script-src a; style-src b");
        p1.intersect(p2);
        assertEquals("script-src a; style-src b", p1.show());

        p1 = parse("plugin-types a/b c/d e/f");
        p2 = parse("plugin-types c/d e/f");
        p1.intersect(p2);
        assertEquals("plugin-types c/d e/f", p1.show());

        p1 = parse("sandbox $ ' % ` !");
        p2 = parse("sandbox ` # '");
        p1.intersect(p2);
        assertEquals("sandbox ' `", p1.show());

        p1 = parse("script-src a b c");
        p2 = parse("script-src b c");
        p1.intersect(p2);
        assertEquals("script-src b c", p1.show());

        p1 = parse("script-src a b c");
        p2 = parse("default-src 'none'; script-src b c");
        p1.intersect(p2);
        assertEquals("script-src b c; default-src", p1.show());

        p1 = parse("default-src *; script-src *; style-src *:80");
        p2 = parse("default-src 'self'; script-src a");
        p1.intersect(p2);
        assertEquals("style-src; default-src 'self'; script-src a", p1.show());

        p1 = parse("default-src 'self'; script-src a");
        p2 = parse("default-src *; script-src *; style-src *:80");
        p1.intersect(p2);
        assertEquals("default-src 'self'; script-src a; style-src", p1.show());

        p1 = ParserWithLocation.parse("script-src a", URI.parse("https://origin"));
        p2 = parse("script-src b; report-uri /x");
        try {
            p1.intersect(p2);
            fail();
        } catch (IllegalArgumentException e1) {
            assertEquals("Cannot merge policies if either policy contains a report-uri directive.", e1.getMessage());
        }

        p1 = parse("script-src a");
        p2 = parse("script-src b; report-uri /x");
        try {
            p1.intersect(p2);
            fail();
        } catch (IllegalArgumentException e1) {
            assertEquals("Cannot merge policies if either policy contains a report-uri directive.", e1.getMessage());
        }

        p1 = parse("script-src 'none'");
        p2 = parse("script-src b; report-uri /x");
        try {
            p1.intersect(p2);
            fail();
        } catch (IllegalArgumentException e1) {
            assertEquals("Cannot merge policies if either policy contains a report-uri directive.", e1.getMessage());
        }

        p1 = Parser.parse("default-src 'self'; script-src https://origin1", "https://origin1");
        p2 = Parser.parse("script-src https://origin1;", "https://origin2");
        p1.intersect(p2);
        assertEquals("default-src 'self'", p1.show());

        p1 = parse("script-src a; report-uri /a");
        p2 = parse("script-src b");
        try {
            p1.intersect(p2);
            fail();
        } catch (IllegalArgumentException e1) {
            assertEquals("Cannot merge policies if either policy contains a report-uri directive.", e1.getMessage());
        }
    }

    @Test public void testNone() {
        Policy p1, p2;

        // union
        p1 = parse("script-src 'none'");
        p2 = parse("script-src a");
        p1.union(p2);
        assertEquals("script-src a", p1.show());

        p1 = parse("script-src a");
        p2 = parse("script-src 'none'");
        p1.union(p2);
        assertEquals("script-src a", p1.show());

        p1 = parse("script-src");
        p2 = parse("script-src 'none'");
        p1.union(p2);
        assertEquals("script-src", p1.show());

        p1 = parse("script-src 'none'");
        p2 = parse("script-src 'none'");
        p1.union(p2);
        assertEquals("script-src", p1.show());


        // intersection
        p1 = parse("script-src 'none'");
        p2 = parse("script-src a");
        p1.intersect(p2);
        assertEquals("script-src", p1.show());

        p1 = parse("script-src a");
        p2 = parse("script-src 'none'");
        p1.intersect(p2);
        assertEquals("script-src", p1.show());

        p1 = parse("script-src");
        p2 = parse("script-src 'none'");
        p1.intersect(p2);
        assertEquals("script-src", p1.show());

        p1 = parse("script-src 'none'");
        p2 = parse("script-src 'none'");
        p1.intersect(p2);
        assertEquals("script-src", p1.show());
    }

    @Test
    public void testUnionReportUri() {
        Policy p1, p2;

        try {
            p1 = parse("script-src a; report-uri /a");
            p2 = parse("script-src b");
            p1.union(p2);
            fail();
        } catch (IllegalArgumentException e1) {
            assertEquals("Cannot merge policies if either policy contains a report-uri directive.",
                e1.getMessage());
        }

        p1 = parse("default-src a b ");
        p2 = parse("default-src; script-src x; style-src y");
        p1.union(p2);
        assertEquals("default-src a b; script-src a b x; style-src a b y", p1.show());
    }

    @Test
    public void testCannotMergeDifferentDirectives() {
        HostSource h = new HostSource(null, "a", Constants.EMPTY_PORT, null);
        StyleSrcDirective d1 = new StyleSrcDirective(Collections.singleton(h));
        ScriptSrcDirective d2 = new ScriptSrcDirective(Collections.singleton(h));

        try {
            d1.union(d2);
        } catch (IllegalArgumentException e) {
            assertEquals(
                "class com.shapesecurity.salvation.directives.StyleSrcDirective can be unioned with class com.shapesecurity.salvation.directives.StyleSrcDirective, but found class com.shapesecurity.salvation.directives.ScriptSrcDirective",
                e.getMessage());
        }

        try {
            d1.intersect(d2);
        } catch (IllegalArgumentException e) {
            assertEquals(
                "class com.shapesecurity.salvation.directives.StyleSrcDirective can be intersected with class com.shapesecurity.salvation.directives.StyleSrcDirective, but found class com.shapesecurity.salvation.directives.ScriptSrcDirective",
                e.getMessage());
        }
    }

    @Test
    public void testUnionDirective() {
        Policy p;
        Set<SourceExpression> set = new LinkedHashSet<>();

        p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
        set.add(new HostSource("http", "abc.com", 80, "/"));
        StyleSrcDirective d1 = new StyleSrcDirective(set);
        p.unionDirective(d1);
        assertEquals(
            "default-src 'self'; script-src a; report-uri http://example.com/z; style-src 'self' http://abc.com/",
            p.show());

        set.clear();
        p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
        set.add(new HostSource("http", "abc.com", 80, "/"));
        DefaultSrcDirective d2 = new DefaultSrcDirective(set);
        p.unionDirective(d2);
        assertEquals(
            "default-src 'self' http://abc.com/; script-src a; report-uri http://example.com/z",
            p.show());

        set.clear();
        p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
        set.add(new HostSource("http", "abc.com", 80, "/"));
        set.add(HostSource.WILDCARD);
        DefaultSrcDirective d3 = new DefaultSrcDirective(set);
        p.unionDirective(d3);
        assertEquals("script-src a; report-uri http://example.com/z", p.show());

        set.clear();
        p = Parser.parse("", "http://example.com");
        set.add(new NonceSource("Q-ecAIccSGatv6lJrCBVARPr"));

        ScriptSrcDirective scriptSrcDirective = new ScriptSrcDirective(set);
        StyleSrcDirective styleSrcDirective = new StyleSrcDirective(set);

        p.unionDirective(scriptSrcDirective);
        p.unionDirective(styleSrcDirective);
        assertEquals("script-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr' *; style-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr' *", p.show());
    }

    @Test
    public void testIntersectDirective() {
        Policy p;
        Set<SourceExpression> set = new LinkedHashSet<>();

        p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
        set.add(new HostSource("http", "abc.com", 80, "/"));
        StyleSrcDirective d1 = new StyleSrcDirective(set);
        p.intersectDirective(d1);
        assertEquals(
            "default-src 'self'; script-src a; report-uri http://example.com/z; style-src",
            p.show());

        set.clear();
        p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
        set.add(new HostSource("http", "abc.com", 80, "/"));
        DefaultSrcDirective d2 = new DefaultSrcDirective(set);
        p.intersectDirective(d2);
        assertEquals(
            "default-src; script-src a; report-uri http://example.com/z",
            p.show());

        set.clear();
        p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
        set.add(new HostSource("http", "abc.com", 80, "/"));
        set.add(HostSource.WILDCARD);
        DefaultSrcDirective d3 = new DefaultSrcDirective(set);
        p.intersectDirective(d3);
        assertEquals("default-src 'self'; script-src a; report-uri http://example.com/z", p.show());

        set.clear();
        p = Parser.parse("", "http://example.com");
        set.add(new NonceSource("Q-ecAIccSGatv6lJrCBVARPr"));

        ScriptSrcDirective scriptSrcDirective = new ScriptSrcDirective(set);
        StyleSrcDirective styleSrcDirective = new StyleSrcDirective(set);

        p.intersectDirective(scriptSrcDirective);
        p.intersectDirective(styleSrcDirective);
        assertEquals("script-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'; style-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'", p.show());
    }

}
