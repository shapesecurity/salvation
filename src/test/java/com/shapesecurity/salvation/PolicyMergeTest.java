package com.shapesecurity.salvation;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.HostSource;
import com.shapesecurity.salvation.directiveValues.NonceSource;
import com.shapesecurity.salvation.directiveValues.SourceExpression;
import com.shapesecurity.salvation.directives.DefaultSrcDirective;
import com.shapesecurity.salvation.directives.ScriptSrcDirective;
import com.shapesecurity.salvation.directives.StyleSrcDirective;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PolicyMergeTest extends CSPTest {

	@Test
	public void testUnion() {
		Policy p1, p2;

		p1 = Parser.parse("default-src aaa", "https://origin1.com");
		p2 = Parser.parse("default-src 'self'", "https://origin2.com");
		p1.union(p2);
		assertEquals("default-src aaa https://origin2.com", p1.show());

		p1 = Parser.parse("default-src d; connect-src a; script-src a; media-src a;", "https://origin1.com");
		p2 = Parser
				.parse("default-src; img-src b; style-src b; font-src b; child-src b; object-src b; manifest-src b; prefetch-src b;", "https://origin2.com");
		p1.union(p2);
		assertEquals(
				"connect-src a; script-src a; media-src a; worker-src a b; style-src d b; img-src d b; child-src d b; font-src d b; object-src d b; manifest-src d b; prefetch-src d b",
				p1.show());

		p1 = Parser.parse("default-src aaa; script-src bbb", "https://origin1.com");
		Set<SourceExpression> set = new LinkedHashSet<>();
		set.add(new HostSource(null, "ccc", -1, null));
		ScriptSrcDirective scriptSrcDirective = new ScriptSrcDirective(set);
		p1.unionDirective(scriptSrcDirective);
		assertEquals(
			"default-src aaa; script-src bbb ccc",
			p1.show());
	}

	@Test
	public void testUnionNonFetchDirectives() {
		Policy p1, p2;

		p1 = Parser.parse("form-action aaa; frame-ancestors bbb; navigate-to ccc", "https://origin1.com");
		p2 = Parser.parse("form-action 'self'; frame-ancestors 'self'; navigate-to 'self'", "https://origin2.com");
		p1.union(p2);
		// TODO expand 'self' for ancestor-source-list
		assertEquals("form-action aaa https://origin2.com; frame-ancestors bbb 'self'; navigate-to ccc https://origin2.com", p1.show());

		p1 = Parser.parse("default-src a ", "https://origin1.com");
		p2 = Parser
				.parse("default-src; form-action a; frame-ancestors b; navigate-to c", "https://origin2.com");
		p1.union(p2);
		assertEquals(
				"default-src a",
				p1.show());

		p1 = Parser.parse("form-action aaa; frame-ancestors bbb; navigate-to ccc", "https://origin1.com");
		p2 = Parser.parse("script-src a", "https://origin1.com");
		p1.union(p2);
		assertEquals("", p1.show());

		p1 = Parser.parse("frame-ancestors bbb;", "https:" + "//origin1.com");
		p2 = Parser.parse("script-src a", "https://origin1.com");
		p1.union(p2);
		assertEquals("", p1.show());

		p1 = Parser.parse("", "https://origin1.com");
		p2 = Parser.parse("script-src a", "https://origin1.com");
		p1.union(p2);
		assertEquals("", p1.show());
	}

	@Test
	public void testUnionDefaultSrc() {
		Policy p1, p2;

		p1 = parse("default-src a b");
		p2 = parse("default-src; script-src x; style-src y");
		p1.union(p2);
		assertEquals("default-src a b; script-src a b x; style-src a b y", p1.show());

		p1 = parse("default-src a b");
		p2 = parse("default-src; script-src-elem a b; script-src-attr a b; style-src-elem a b; style-src-attr a b");
		p1.union(p2);
		assertEquals("default-src a b", p1.show());

		p1 = parse("default-src *; script-src");
		p2 = parse("default-src; script-src b");
		p1.union(p2);
		assertEquals("default-src *; script-src b", p1.show());

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

		p1 = parse("default-src 'strict-dynamic' 'nonce-1234' b; script-src a");
		p2 = parse("default-src a");
		p1.union(p2);
		assertEquals("default-src 'strict-dynamic' 'nonce-1234' b a; script-src a", p1.show());
	}

	@Test
	public void testIntersect() {
		Policy p1, p2;

		p1 = parse("default-src *;");
		p2 = parse("script-src-elem a b; script-src-attr c d; style-src-elem a b; style-src-attr c d");
		p1.intersect(p2);
		assertEquals("default-src *; script-src-elem a b; script-src-attr c d; style-src-elem a b; style-src-attr c d", p1.show());

		p1 = parse("default-src 'none';");
		p2 = parse("default-src *;");
		p1.intersect(p2);
		assertEquals("default-src", p1.show());

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
		assertEquals("default-src 'self'; style-src; script-src a", p1.show());

		p1 = parse("default-src 'self'; script-src a");
		p2 = parse("default-src *; script-src *; style-src *:80");
		p1.intersect(p2);
		assertEquals("default-src 'self'; script-src a; style-src", p1.show());

		p1 = parse("default-src 'self' 'strict-dynamic'; script-src a");
		p2 = parse("default-src *; script-src *; style-src *:80");
		p1.intersect(p2);
		assertEquals("default-src 'self' 'strict-dynamic'; script-src a; style-src", p1.show());

		p1 = parse("prefetch-src a");
		p2 = parse("script-src a; style-src b");
		p1.intersect(p2);
		assertEquals("prefetch-src a; script-src a; style-src b", p1.show());

		p1 = parse("prefetch-src a");
		p2 = parse("prefetch-src a; style-src b");
		p1.intersect(p2);
		assertEquals("prefetch-src a; style-src b", p1.show());

		p1 = ParserWithLocation.parse("script-src a", URI.parse("https://origin"));
		p2 = parse("script-src b; report-uri /x");
		try {
			p1.intersect(p2);
			fail();
		} catch (IllegalArgumentException e1) {
			assertEquals("Cannot merge policies if either policy contains a report-uri directive.", e1.getMessage());
		}

		p1 = ParserWithLocation.parse("script-src a", URI.parse("https://origin"));
		p2 = parse("script-src b; report-to abc");
		try {
			p1.intersect(p2);
			fail();
		} catch (IllegalArgumentException e1) {
			assertEquals("Cannot merge policies if either policy contains a report-to directive.", e1.getMessage());
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

		p1 = parse("script-src a; report-to bbb");
		p2 = parse("report-to aaa");
		try {
			p1.intersect(p2);
			fail();
		} catch (IllegalArgumentException e1) {
			assertEquals("Cannot merge policies if either policy contains a report-to directive.", e1.getMessage());
		}
	}

	@Test
	public void testIntersectNonFetchDirectives() {
		Policy p1, p2;

		p1 = parse("form-action 'none';");
		p2 = parse("form-action *;");
		p1.intersect(p2);
		assertEquals("form-action", p1.show());

		p1 = parse("frame-ancestors 'none';");
		p2 = parse("frame-ancestors *;");
		p1.intersect(p2);
		assertEquals("frame-ancestors", p1.show());

		p1 = parse("navigate-to 'none';");
		p2 = parse("navigate-to *;");
		p1.intersect(p2);
		assertEquals("navigate-to", p1.show());

		p1 = parse("form-action a;");
		p2 = parse("form-action a;");
		p1.intersect(p2);
		assertEquals("form-action a", p1.show());

		p1 = parse("frame-ancestors a;");
		p2 = parse("frame-ancestors a;");
		p1.intersect(p2);
		assertEquals("frame-ancestors a", p1.show());

		p1 = parse("navigate-to a;");
		p2 = parse("navigate-to a;");
		p1.intersect(p2);
		assertEquals("navigate-to a", p1.show());

		p1 = parse("form-action a b c;");
		p2 = parse("form-action a;");
		p1.intersect(p2);
		assertEquals("form-action a", p1.show());

		p1 = parse("frame-ancestors a b c;");
		p2 = parse("frame-ancestors a;");
		p1.intersect(p2);
		assertEquals("frame-ancestors a", p1.show());

		p1 = parse("navigate-to a b c;");
		p2 = parse("navigate-to a;");
		p1.intersect(p2);
		assertEquals("navigate-to a", p1.show());

		p1 = parse("navigate-to a b c;");
		p2 = parse("script-src zzz");
		p1.intersect(p2);
		assertEquals("navigate-to a b c; script-src zzz", p1.show());

		p1 = Parser.parse("", "https://origin1.com");
		p2 = Parser.parse("script-src a", "https://origin1.com");
		p1.intersect(p2);
		assertEquals("script-src a", p1.show());
	}

	@Test
	public void testNone() {
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
			assertEquals("Cannot merge policies if either policy contains a report-uri directive.", e1.getMessage());
		}

		try {
			p1 = parse("script-src a; report-to /a");
			p2 = parse("script-src b");
			p1.union(p2);
		} catch (IllegalArgumentException e1) {
			assertEquals("Cannot merge policies if either policy contains a report-to directive.", e1.getMessage());
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
		assertEquals("default-src 'self' http://abc.com/; script-src a; report-uri http://example.com/z", p.show());

		set.clear();
		p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
		set.add(new HostSource("http", "abc.com", 80, "/"));
		set.add(HostSource.WILDCARD);
		DefaultSrcDirective d3 = new DefaultSrcDirective(set);
		p.unionDirective(d3);
		assertEquals("default-src *; script-src a; report-uri http://example.com/z", p.show());

		set.clear();
		p = Parser.parse("", "http://example.com");
		set.add(new NonceSource("Q-ecAIccSGatv6lJrCBVARPr"));

		ScriptSrcDirective scriptSrcDirective = new ScriptSrcDirective(set);
		StyleSrcDirective styleSrcDirective = new StyleSrcDirective(set);

		p.unionDirective(scriptSrcDirective);
		p.unionDirective(styleSrcDirective);
		assertEquals("",
				p.show());
	}

	@Test
	public void testIntersectDirective() {
		Policy p;
		Set<SourceExpression> set = new LinkedHashSet<>();

		p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
		set.add(new HostSource("http", "abc.com", 80, "/"));
		StyleSrcDirective d1 = new StyleSrcDirective(set);
		p.intersectDirective(d1);
		assertEquals("default-src 'self'; script-src a; report-uri http://example.com/z; style-src", p.show());

		set.clear();
		p = Parser.parse("default-src 'self'; script-src a; report-uri /z", "http://example.com");
		set.add(new HostSource("http", "abc.com", 80, "/"));
		DefaultSrcDirective d2 = new DefaultSrcDirective(set);
		p.intersectDirective(d2);
		assertEquals("default-src; script-src a; report-uri http://example.com/z", p.show());

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
		assertEquals("script-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'; style-src 'nonce-Q-ecAIccSGatv6lJrCBVARPr'",
				p.show());
	}

	@Test
	public void testIntersectionIsCaseInsensitive() {
		Policy p = parse("default-src 'self' example.org; ");
		Policy q = parse("default-src 'self' EXAMPLE.ORG; ");
		p.intersect(q);
		assertEquals("default-src 'self' example.org", p.show());

		p = parse("default-src 'self' EXAMPLE.ORG; ");
		q = parse("default-src 'self' example.org; ");
		p.intersect(q);
		assertEquals("default-src 'self' EXAMPLE.ORG", p.show());

		p = parse("default-src 'self' *.abc; ");
		q = parse("default-src 'self' *.aBc; ");
		p.intersect(q);
		assertEquals("default-src 'self' *.abc", p.show());

		p = parse("default-src 'self' *.abc/a/b/c/; ");
		q = parse("default-src 'self' *.ABc/a/B/c/; ");
		p.union(q);
		assertEquals("default-src 'self' *.abc/a/b/c/ *.ABc/a/B/c/", p.show());

		p = parse("default-src 'self' *.abc/a; ");
		q = parse("default-src 'self' *.ABc/A; ");
		p.intersect(q);
		assertEquals("default-src 'self'", p.show());

		p = parse("default-src 'self' http://abc/a; ");
		q = parse("default-src 'self' hTtP://ABc/a; ");
		p.intersect(q);
		assertEquals("default-src 'self' http://abc/a", p.show());
	}

	@Test
	public void testUnionCaseIsInsensitive() {
		Policy p = parse("default-src 'self' example.org; ");
		Policy q = parse("default-src 'self' EXAMPLE.ORG; ");
		p.union(q);
		assertEquals("default-src 'self' example.org", p.show());

		p = parse("default-src 'self' EXAMPLE.ORG; ");
		q = parse("default-src 'self' example.org; ");
		p.union(q);
		assertEquals("default-src 'self' EXAMPLE.ORG", p.show());

		p = parse("default-src 'self' *.abc; ");
		q = parse("default-src 'self' *.ABc; ");
		p.union(q);
		assertEquals("default-src 'self' *.abc", p.show());

		p = parse("default-src 'self' *.abc/a; ");
		q = parse("default-src 'self' *.ABc/a; ");
		p.union(q);
		assertEquals("default-src 'self' *.abc/a", p.show());

		p = parse("default-src 'self' *.abc/a/b/c/; ");
		q = parse("default-src 'self' *.ABc/a/B/c/; ");
		p.union(q);
		assertEquals("default-src 'self' *.abc/a/b/c/ *.ABc/a/B/c/", p.show());

		p = parse("default-src 'self' *.abc/a; ");
		q = parse("default-src 'self' *.ABc/A; ");
		p.union(q);
		assertEquals("default-src 'self' *.abc/a *.ABc/A", p.show());

		p = parse("default-src 'self' http://abc/a; ");
		q = parse("default-src 'self' hTtP://ABc/a; ");
		p.union(q);
		assertEquals("default-src 'self' http://abc/a", p.show());
	}

	@Test
	public void testUnionChildSrc() {
		Policy p = parse("child-src 'self' example.org; ");
		Policy q = parse("child-src 'self' EXAMPLE.ORG; ");
		p.union(q);
		assertEquals("child-src 'self' example.org", p.show());

		p = parse("child-src 'self' EXAMPLE.ORG; ");
		q = parse("child-src 'self' example.org; ");
		p.union(q);
		assertEquals("child-src 'self' EXAMPLE.ORG", p.show());

		p = parse("child-src a; ");
		q = parse("worker-src a");
		p.union(q);
		p.postProcessOptimisation();
		assertEquals("worker-src a", p.show());

		p = parse("child-src a; ");
		q = parse("frame-src a ");
		p.union(q);
		p.postProcessOptimisation();
		assertEquals("frame-src a", p.show());

		p = parse("child-src a b");
		q = parse("child-src; worker-src x; frame-src y");
		p.union(q);
		p.postProcessOptimisation();
		assertEquals("child-src a b; frame-src a b y; worker-src a b x", p.show());

		p = parse("child-src *; worker-src");
		q = parse("child-src; worker-src b");
		p.union(q);
		assertEquals("child-src *; worker-src b", p.show());

		p = parse("child-src *; frame-src");
		q = parse("child-src; frame-src b");
		p.union(q);
		assertEquals("child-src *; frame-src b", p.show());

		p = parse("child-src a");
		q = parse("child-src; worker-src b");
		p.union(q);
		assertEquals("child-src a; worker-src a b", p.show());

		p = parse("child-src a; worker-src b");
		q = parse("child-src; worker-src c");
		p.union(q);
		assertEquals("child-src a; worker-src b c", p.show());

		p = parse("child-src; worker-src a; frame-src b");
		q = parse("child-src c");
		p.union(q);
		assertEquals("child-src c; worker-src a c; frame-src b c", p.show());

		p = parse("child-src a; worker-src b");
		q = parse("child-src c; frame-src d");
		p.union(q);
		assertEquals("child-src a c; frame-src a d", p.show());

		p = parse("child-src b; worker-src a");
		q = parse("child-src a");
		p.union(q);
		assertEquals("child-src b a; worker-src a", p.show());

		p = parse("default-src a");
		q = parse("worker-src b; frame-src b;");
		p.union(q);
		assertEquals("frame-src a b; worker-src a b", p.show());
	}

	@Test
	public void testUnionNone() {
		Policy x = Parser.parse("frame-ancestors https://foo.bar", "http://example.com");
		Policy y = Parser.parse("default-src 'none'", "http://example.com");
		x.union(y);
		assertEquals("", x.show());

		x = Parser.parse("frame-ancestors https://foo.bar", "http://example.com");
		y = Parser.parse("default-src 'none'; frame-ancestors;", "http://example.com");
		x.union(y);
		assertEquals("frame-ancestors https://foo.bar", x.show());

		Policy p = parse("frame-ancestors 'none'");
		Policy q = parse("frame-ancestors 'self'");
		p.union(q);
		assertEquals("frame-ancestors 'self'", p.show());

		p = parse("frame-ancestors 'none' 'none'");
		q = parse("frame-ancestors 'self'");
		p.union(q);
		assertEquals("", p.show());

		p = parse("frame-ancestors 'self'");
		q = parse("frame-ancestors 'none'");
		p.union(q);
		assertEquals("frame-ancestors 'self'", p.show());

		p = parse("frame-ancestors a b c");
		q = parse("frame-ancestors 'none'");
		p.union(q);
		assertEquals("frame-ancestors a b c", p.show());

		p = parse("frame-ancestors 'none'");
		q = parse("frame-ancestors 'none'");
		p.union(q);
		assertEquals("frame-ancestors", p.show());

		p = parse("frame-ancestors *");
		q = parse("frame-ancestors 'none'");
		p.union(q);
		assertEquals("frame-ancestors *", p.show());

		p = parse("script-src 'none'");
		q = parse("script-src 'self'");
		p.union(q);
		assertEquals("script-src 'self'", p.show());

		p = parse("");
		q = parse("script-src 'self'");
		p.union(q);
		assertEquals("", p.show());

		p = parse("script-src 'self'");
		q = parse("script-src 'none'");
		p.union(q);
		assertEquals("script-src 'self'", p.show());

		p = parse("script-src a b c");
		q = parse("script-src 'none'");
		p.union(q);
		assertEquals("script-src a b c", p.show());

		p = parse("script-src 'none'");
		q = parse("script-src 'none'");
		p.union(q);
		assertEquals("script-src", p.show());

		p = parse("script-src *");
		q = parse("script-src 'none'");
		p.union(q);
		assertEquals("script-src *", p.show());
	}

	@Test
	public void testMergeCommutativity() {
		String[] policies = new String[] {
			"script-src 'self'",
			"script-src 'none'",
			"script-src a",
			"script-src a custom:",
			"style-src 'self'",
			"style-src 'none'",
			"style-src a",
			"style-src a custom:",
			"default-src 'none'",
			"default-src a",
			"default-src custom:",
			"plugin-types a/b",
			"frame-ancestors 'self'",
			"frame-ancestors 'none'",
			"frame-ancestors a",
			"frame-ancestors a custom:",
			"frame-ancestors custom:",
			"upgrade-insecure-requests",
			"script-src a; frame-ancestors b"
		};

		for (int i = 0; i < policies.length; i++) {
			for (int k = 0; k < policies.length; k++) {
				Policy pq = parse(policies[i]);
				pq.union(parse(policies[k]));

				Policy qp = parse(policies[k]);
				qp.union(parse(policies[i]));

				assertTrue(pq.show() + " ≠ " + qp.show(), pq.equals(qp));
			}
		}

		for (int i = 0; i < policies.length; i++) {
			for (int k = 0; k < policies.length; k++) {
				Policy pq = parse(policies[i]);
				pq.intersect(parse(policies[k]));

				Policy qp = parse(policies[k]);
				qp.intersect(parse(policies[i]));

				assertTrue(pq.show() + " ≠ " + qp.show(), pq.equals(qp));
			}
		}
	}
}
