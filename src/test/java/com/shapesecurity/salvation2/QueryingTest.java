package com.shapesecurity.salvation2;

import com.shapesecurity.salvation2.Policy.PolicyErrorConsumer;
import com.shapesecurity.salvation2.URLs.GUID;
import com.shapesecurity.salvation2.URLs.URI;
import com.shapesecurity.salvation2.URLs.URLWithScheme;
import com.shapesecurity.salvation2.Values.MediaType;
import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class QueryingTest extends TestBase {
	static String EXAMPLE_SHA = "sha512-O7Eu2jwpjbXeJVl/VNkk8uF+eKJq2JU+2CGO5oLwu76QIeLzAJ0VLJEb8fJexoOpAnFBZnZ6+9jlvQ+wEk7Lig=="; // sha512 of 'example'

	@Test
	public void testAllowsFromSource() {
		PolicyInOrigin p;

		p = parse(
				"default-src 'none'; img-src https: 'self' http://abc.am/; style-src https://*.abc.am:*; script-src 'self' https://abc.am https://*.cde.am/a",
				URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsImageFromSource(URI.parseURI("https://a.com/12").orElse(null)));
		assertTrue("resource is allowed", p.allowsImageFromSource(URI.parseURI("https://abc.am").orElse(null)));
		assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parseURI("https://abc.am").orElse(null)));
		assertTrue("resource is allowed", p.allowsImageFromSource(URI.parseURI("https://abc.com/12").orElse(null)));
		assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parseURI("httpS://www.cDE.am/a").orElse(null)));
		assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parseURI("https://www.cde.am/a").orElse(null)));
		assertFalse("resource is not allowed", p.allowsImageFromSource(URI.parseURI("http://a.com/12").orElse(null)));
		assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parseURI("ftp://www.abc.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parseURI("https://www.cde.am/A").orElse(null)));
		assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));

		p = parse("default-src 'none'", "https://abc.com");
		assertFalse("resource is not allowed", p.allowsImageFromSource(URI.parseURI("https://abc.am").orElse(null)));
		assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parseURI("ftp://www.abc.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsScriptFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsWorkerFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));


		p = parse("default-src *:*", "http://abc.com");
		assertTrue("resource is allowed", p.allowsImageFromSource(URI.parseURI("http://abc.am").orElse(null)));
		assertTrue("resource is allowed", p.allowsScriptFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsStyleFromSource(URI.parseURI("ftp://www.abc.am:555").orElse(null)));

		p = parse("default-src 'none'; frame-src http:;", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));

		p = parse("default-src 'none'; worker-src http:;", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsWorkerFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertTrue("resource is allowed", p.allowsWorkerFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));

		p = parse("child-src http:;", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));

		p = parse("frame-src https:; child-src http:;", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsFrameFromSource(URI.parseURI("https://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsFrameFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));

		p = parse("font-src https://font.com http://font.org", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsFontFromSource(URI.parseURI("https://font.com").orElse(null)));
		assertFalse("resource is not allowed", p.allowsFontFromSource(URI.parseURI("https://font.com:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsFontFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsFontFromSource(URI.parseURI("https://someco.net").orElse(null)));

		p = parse("object-src https://object.com http://object.org", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsObjectFromSource(URI.parseURI("https://object.com").orElse(null)));
		assertFalse("resource is not allowed", p.allowsObjectFromSource(URI.parseURI("https://object.com:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsObjectFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsObjectFromSource(URI.parseURI("https://someco.net").orElse(null)));

		p = parse("media-src https://media.com http://media.org", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsMediaFromSource(URI.parseURI("https://media.com").orElse(null)));
		assertFalse("resource is not allowed", p.allowsMediaFromSource(URI.parseURI("https://media.com:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsMediaFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsMediaFromSource(URI.parseURI("https://someco.net").orElse(null)));

		p = parse("manifest-src https://manifest.com http://manifest.org", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("resource is allowed", p.allowsManifestFromSource(URI.parseURI("https://manifest.com").orElse(null)));
		assertFalse("resource is not allowed", p.allowsManifestFromSource(URI.parseURI("https://manifest.com:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsManifestFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsManifestFromSource(URI.parseURI("https://someco.net").orElse(null)));

		p = parse("prefetch-src https://prefetchy.com http://prefetchy.org", URI.parseURI("https://abc.com").orElse(null), PolicyErrorConsumer.ignored);
		assertTrue("resource is allowed", p.allowsPrefetchFromSource(URI.parseURI("https://prefetchy.com").orElse(null)));
		assertFalse("resource is not allowed", p.allowsPrefetchFromSource(URI.parseURI("https://prefetchy.com:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsPrefetchFromSource(URI.parseURI("http://www.def.am:555").orElse(null)));
		assertFalse("resource is not allowed", p.allowsPrefetchFromSource(URI.parseURI("https://someco.net").orElse(null)));

	}

	@Test
	public void testSecureSchemes() {
		PolicyInOrigin p;

		p = parse("script-src http:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src http:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://a").orElse(null)));

		p = parse("script-src http:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://a").orElse(null)));

		p = parse("script-src http:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src http:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ftp://a").orElse(null)));

		p = parse("script-src http:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("sftp://a").orElse(null)));

		p = parse("script-src ws:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src ws:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ws://a").orElse(null)));

		p = parse("script-src ws:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("wss://a").orElse(null)));

		p = parse("script-src ws:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src ws:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ftp://a").orElse(null)));

		p = parse("script-src ws:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("sftp://a").orElse(null)));

		p = parse("script-src wss:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src wss:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://a").orElse(null)));

		p = parse("script-src wss:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("wss://a").orElse(null)));

		p = parse("script-src wss:;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src wss:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ftp://a").orElse(null)));

		p = parse("script-src wss:;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("sftp://a").orElse(null)));

		p = parse("script-src a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src https://a;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src http://a;", "https://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src http://a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src http://a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src https://a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src ws://a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src wss://a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));

		p = parse("script-src wss://a;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://a").orElse(null)));

		p = parse("script-src wss://a;", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a").orElse(null)));

		p = parse("script-src ws://a;", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://a").orElse(null)));
	}


	@Test
	public void testAllowsUnsafeInline() {
		PolicyInOrigin p;

		p = parse("script-src https: 'self' http://a", URI.parseURI("https://abc.com").orElse(null));
		assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
		assertTrue("inline style is allowed", p.allowsUnsafeInlineStyle()); // NB changed
		p = parse("script-src https: 'self' http://a 'unsafe-inline'", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("inline script is allowed", p.allowsUnsafeInlineScript());
		assertTrue("inline style is allowed", p.allowsUnsafeInlineStyle()); // NB changed

		p = parse("style-src https: 'self' http://a", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("inline script is not allowed", p.allowsUnsafeInlineScript()); // NB chagned
		assertFalse("inline style is not allowed", p.allowsUnsafeInlineStyle());
		p = parse("style-src https: 'self' http://a 'unsafe-inline'", URI.parseURI("https://abc.com").orElse(null));
		assertTrue("inline script is not allowed", p.allowsUnsafeInlineScript()); // NB changed
		assertTrue("inline style is allowed", p.allowsUnsafeInlineStyle());

		p = parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
		assertTrue("inline script is allowed", p.allowsUnsafeInlineScript());
		assertTrue("inline style is allowed", p.allowsUnsafeInlineStyle());
		assertTrue("script hash is allowed", p.policy.allowsInlineScript(Optional.empty(), Optional.of("anything"), Optional.empty()));
		assertTrue("style hash is allowed", p.policy.allowsInlineStyle(Optional.empty(), Optional.of("anything")));

		p = parse("default-src * 'unsafe-inline' 'nonce-123'", "https://abc.com");
		assertFalse("inline script is not allowed", p.allowsUnsafeInlineScript());
	}

	@Test
	public void testAllowsPlugin() {
		assertTrue("plugin is allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("A/b")));
		assertTrue("plugin is allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("a/B")));
		assertTrue("plugin is allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("A/B")));
		assertTrue("plugin is allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("a/b")));
		assertTrue("plugin is not allowed", parse("default-src 'none'", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("z/b"))); // NB changed
		assertFalse("plugin is not allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("z/b")));
		assertFalse("plugin is not allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("a/d")));
		assertFalse("plugin is not allowed", parse("plugin-types a/b c/d", PolicyErrorConsumer.ignored).allowsPlugin(MediaType.parseMediaType("/b")));
	}

	@Test
	public void testAllowsHash() {
		Policy p;

		String wellFormedMatching = "sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==";
		String wellFormedNotMatching = "sha512-cGl6ZGE";
		String malformed = "sha257-a";

		p = parse(
				"script-src 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
		assertTrue("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				wellFormedMatching), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("script hash is not allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				wellFormedNotMatching), Optional.empty(), Optional.empty(), Optional.empty()));

		// Malformed hashes aren't checked at all
		assertTrue("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				malformed + " " + wellFormedMatching), Optional.empty(), Optional.empty(), Optional.empty()));

		assertFalse("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				malformed + " " + wellFormedNotMatching), Optional.empty(), Optional.empty(), Optional.empty()));

		assertFalse("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				malformed + " sha257-b"), Optional.empty(), Optional.empty(), Optional.empty()));

		// All well-formed hashes are checked
		assertFalse("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				wellFormedMatching + " " + wellFormedNotMatching), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				wellFormedNotMatching + " " + wellFormedMatching), Optional.empty(), Optional.empty(), Optional.empty()));

		// Works for all hashes
		p = parse(
				"script-src 'sha256-UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw='");
		assertTrue("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				"sha256-UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw="), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue("script hash is allowed", p.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertFalse("script hash is not allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				wellFormedMatching), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("script hash is not allowed", p.allowsInlineScript(Optional.empty(), Optional.of("example2"), Optional.empty()));

		p = parse(
				"script-src 'sha384-/u6/iE9tq+bsqNaONz1r5IjNql63ZOiVKQM2/+n/lpaG8qnTYumou93257LhRV8t'");
		assertTrue("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				"sha384-/u6/iE9tq+bsqNaONz1r5IjNql63ZOiVKQM2/+n/lpaG8qnTYumou93257LhRV8t"), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue("script hash is allowed", p.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertFalse("script hash is not allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				wellFormedMatching), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("script hash is not allowed", p.allowsInlineScript(Optional.empty(), Optional.of("example2"), Optional.empty()));


		p = parse(
				"style-src '" + EXAMPLE_SHA + "'");
		assertTrue("style hash is allowed", p.allowsInlineStyle(Optional.empty(), Optional.of("example")));
		assertFalse("style hash is not allowed", p.allowsInlineStyle(Optional.empty(), Optional.of("example2")));

		p = parse("default-src 'none'");
		assertFalse("script hash is not allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				"sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=="), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("style hash is not allowed", p.allowsInlineStyle(Optional.empty(), Optional.of("example2")));

		p = parse("default-src * 'unsafe-inline' 'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=='");
		assertTrue("script hash is allowed", p.allowsExternalScript(Optional.empty(), Optional.of(
				"sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg=="), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("unknown script hash is not allowed", p.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("unknown script is not allowed", p.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("unknown style is not allowed", p.allowsInlineStyle(Optional.empty(), Optional.empty()));
	}

	@Test
	public void testAllowsNonce() {
		Policy p;

		p = parse("script-src 'nonce-0gQAAA=='");
		assertTrue("script nonce is allowed", p.allowsInlineScript(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty()));
		assertTrue("script nonce is allowed", p.allowsExternalScript(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("script nonce is not allowed", p.allowsInlineScript(Optional.of("cGl6ZGE="), Optional.empty(), Optional.empty()));
		assertFalse("script nonce is allowed", p.allowsExternalScript(Optional.of("cGl6ZGE="), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));

		p = parse("style-src 'nonce-0gQAAA=='");
		assertTrue("style nonce is allowed", p.allowsInlineStyle(Optional.of("0gQAAA=="), Optional.empty()));
		assertTrue("style nonce is allowed", p.allowsExternalStyle(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty()));
		assertFalse("style nonce is not allowed", p.allowsInlineStyle(Optional.of("cGl6ZGE="), Optional.empty()));
		assertFalse("style nonce is not allowed", p.allowsExternalStyle(Optional.of("cGl6ZGE="), Optional.empty(), Optional.empty()));

		p = parse("default-src 'none'");
		assertFalse("script nonce is not allowed", p.allowsInlineScript(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty()));
		assertFalse("script nonce is not allowed", p.allowsExternalScript(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("style nonce is not allowed", p.allowsInlineStyle(Optional.of("0gQAAA=="), Optional.empty()));
		assertFalse("style nonce is not allowed", p.allowsExternalStyle(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty()));

		p = parse("default-src * 'unsafe-inline' 'nonce-0gQAAA=='");
		assertTrue("script nonce is allowed", p.allowsInlineScript(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty()));
		assertTrue("script nonce is allowed", p.allowsExternalScript(Optional.of("0gQAAA=="), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("script wrong nonce is not allowed", p.allowsInlineScript(Optional.of("cGl6ZGE="), Optional.empty(), Optional.empty()));
		assertFalse("script wrong nonce is not allowed", p.allowsExternalScript(Optional.of("cGl6ZGE="), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("unsafe script is not allowed", p.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("unsafe script is not allowed", p.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("unsafe style is not allowed", p.allowsInlineStyle(Optional.empty(), Optional.empty()));
		assertFalse("unsafe style is not allowed", p.allowsExternalStyle(Optional.empty(), Optional.empty(), Optional.empty()));

		// Empty nonces are explicitly disallowed
		p = Policy.parseSerializedCSP("default-src 'nonce-'", Policy.PolicyErrorConsumer.ignored);
		assertFalse("script nonce is allowed", p.allowsExternalScript(Optional.of(""), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse("style nonce is allowed", p.allowsExternalStyle(Optional.of(""), Optional.empty(), Optional.empty()));
	}


	@Test
	public void testAllowsScriptAttributeWithHash() {
		Policy p;

		p = parse("script-src 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertTrue("attribute with hash is allowed", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));

		p = parse(
				"script-src-attr 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertTrue("attribute with hash is allowed", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));

		p = parse(
				"default-src 'none'; script-src-elem 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));

		p = parse("style-src 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertTrue("attribute with hash is allowed", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));

		p = parse(
				"style-src-attr 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertTrue("attribute with hash is allowed", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));

		p = parse(
				"default-src 'none'; style-src-elem 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));

		p = parse("default-src 'unsafe-hashes' '" + EXAMPLE_SHA + "'");
		assertTrue("attribute with hash is allowed", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));
		assertTrue("attribute with hash is allowed", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));


		p = parse("script-src '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));

		p = parse("style-src '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));

		p = parse(
				"script-src-attr '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));

		p = parse(
				"style-src-attr '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));

		p = parse(
				"default-src 'none'; script-src-elem '" + EXAMPLE_SHA + "'; style-src-elem '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));

		p = parse("default-src '" + EXAMPLE_SHA + "'");
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsScriptAsAttribute(Optional.of("example2")));
		assertFalse("attribute with hash is not allowed without unsafe-hashes", p.allowsStyleAsAttribute(Optional.of("example")));
		assertFalse("attribute with wrong hash is not allowed", p.allowsStyleAsAttribute(Optional.of("example2")));
	}

	@Test
	public void testAllowsConnect() {
		PolicyInOrigin p;

		p = parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "https://abc.com");
		assertTrue("connect is allowed", p.allowsConnection(URI.parseURI("https://abc.com").orElse(null)));
		assertTrue("connect is allowed", p.allowsConnection(URI.parseURI("http://good.com/").orElse(null)));
		assertTrue("connect is allowed", p.allowsConnection(URI.parseURI("https://good.com/").orElse(null)));
		assertFalse("connect is not allowed", p.allowsConnection(URI.parseURI("http://aaa.good.com/").orElse(null)));
		assertTrue("connect is allowed", p.allowsConnection(URI.parseURI("wss://abc.com/").orElse(null))); // NB changed, see https://github.com/w3c/webappsec-csp/issues/429
		assertFalse("connect is not allowed", p.allowsConnection(URI.parseURI("http://abc.com/").orElse(null)));
		assertFalse("connect is allowed", p.allowsConnection(URI.parseURI("ws://abc.com/").orElse(null)));

		p = parse("default-src *:* 'unsafe-inline'; connect-src 'self' http://good.com/", "http://abc.com");
		assertTrue("connect is allowed", p.allowsConnection(URI.parseURI("ws://abc.com/").orElse(null)));

		p = parse("connect-src data:", "http://abc.com");
		assertTrue("connect is allowed", p.allowsConnection(GUID.parseGUID("data:foo").orElse(null)));
	}

	@Test
	public void testAllowsFrameAncestor() {
		PolicyInOrigin p;

		p = parse("", "https://abc.com");
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("https://abc.com").orElse(null)));
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("ftp://cde.com").orElse(null)));

		// frame-ancestors does not fall back to default-src
		p = parse("default-src 'none'", "https://abc.com");
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("https://abc.com").orElse(null)));
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("ftp://cde.com").orElse(null)));

		p = parse("frame-ancestors 'none'", "https://abc.com");
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("ftp://cde.com").orElse(null)));
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("https://abc.com").orElse(null)));

		p = parse("frame-ancestors 'self'", "https://abc.com");
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("ftp://cde.com").orElse(null)));
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("https://abc.com").orElse(null)));

		p = parse("frame-ancestors https:", "https://abc.com");
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("ftp://cde.com").orElse(null)));
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("http://cde.com").orElse(null)));
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("http://abc.com").orElse(null)));
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("https://abc.com").orElse(null)));

		p = parse("frame-ancestors http://example.com https:", "https://abc.com");
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("ftp://cde.com").orElse(null)));
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("http://cde.com").orElse(null)));
		assertFalse("frame ancestor is not allowed", p.allowsFrameAncestor(URI.parseURI("http://abc.com").orElse(null)));
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("https://example.com").orElse(null)));
		assertTrue("frame ancestor is allowed", p.allowsFrameAncestor(URI.parseURI("http://example.com").orElse(null)));
	}


	@Test
	public void testHosts() {
		PolicyInOrigin p;

		p = parse("script-src http://*.example.com/a", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://A.example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.EXAMPLE.COM/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.b.example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com.org/a").orElse(null)));

		p = parse("script-src http://*.EXAMPLE.COM/a", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://A.example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.EXAMPLE.COM/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.b.example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com.org/a").orElse(null)));

		p = parse("script-src http://example.com/a", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://EXAMPLE.COM/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a.example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://A.example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a.EXAMPLE.COM/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com.org/a").orElse(null)));

		p = parse("script-src http://EXAMPLE.COM/a", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://EXAMPLE.COM/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a.example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://A.example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://a.EXAMPLE.COM/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com.org/a").orElse(null)));

		p = parse("script-src http://127.0.0.1/a", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://127.0.0.1/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://127.0.0.1.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://127.0.0.2/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://127.0.0.1.1/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://10.10.0.1/a").orElse(null)));

		p = parse("script-src http://192.168.1.1/a", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://192.168.1.1/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://192.168.0.1/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://127.0.0.1/a").orElse(null)));
	}


	@Test
	public void testPaths() {
		PolicyInOrigin p;

		p = parse("script-src example.com/a", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com////a").orElse(null)));

		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/A").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/c").orElse(null)));

		p = parse("script-src example.com/a/", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/A/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/c").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/A/b/c").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/B/C").orElse(null)));

		p = parse("script-src example.com/a/b", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/B").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/c").orElse(null)));

		p = parse("script-src example.com/a/b/", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/c").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/C").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/A/B/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/A/B/c").orElse(null)));

		p = parse("script-src example.com/a/b/c", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/A/B/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/c").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b/C").orElse(null)));

		p = parse("script-src example.com/a/b%3Bzzz%2Cqqq", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b%3Bzzz").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b%3Bzzz%2Cqqq").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/a/b;zzz,qqq").orElse(null)));

		p = parse("script-src example.com/%21/%24/%26/%27/%28/%29/%2A/%2C/%3A/%3B", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/!/$/&/'/(/)/*/,/:/;").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/%21/%24/%26/%27/%28/%29/%2A/%2C/%3A/%3B").orElse(null)));

		// TODO: this is valid in Chrome
		//		p = parse("script-src example.com/%GG", "http://example.com");
		//		assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%GG")));
		// TODO: this is valid in Chrome
		//		p = parse("script-src example.com/%%GGpath", "http://example.com");
		//		assertTrue(p.allowsScriptFromSource(URI.parse("http://example.com/%GG")));

		p = parse("script-src example.com/%C3%AF/", "http://example.com");
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com/%EF/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/%C3%AF/").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/%C3%AF/%65").orElse(null)));
	}


	@Test
	public void testLocalSchemes() {
		PolicyInOrigin p;
		
		p = parse("script-src *.example.com data: blob:; frame-ancestors data: about:", "http://example.com");
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("DATA:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("blob:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("BLOB:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("about:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("ABOUT:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("DATA:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("about:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("ABOUT:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("blob:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("BLOB:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("script-src *.example.com DATA: BLOB:; frame-ancestors DATA: ABOUT:", "http://example.com");
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("DATA:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("blob:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("BLOB:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("about:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("ABOUT:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("DATA:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("about:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("ABOUT:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("blob:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("BLOB:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("script-src *.example.com custom-scheme:; frame-ancestors custom.scheme2:", "http://example.com");
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("custom-scheme:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("BLOB:").orElse(null)));
		assertFalse(p.allowsFrameAncestor(GUID.parseGUID("custom-scheme:").orElse(null)));
		assertTrue(p.allowsFrameAncestor(GUID.parseGUID("custom.scheme2:").orElse(null)));
	}

	@Test
	public void testStrictDynamic() {
		PolicyInOrigin p;

		p = parse("default-src 'unsafe-inline' 'strict-dynamic'", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.policy.allowsScriptAsAttribute(Optional.of("example")));
		assertTrue(p.allowsUnsafeInlineStyle());
		assertTrue(p.policy.allowsStyleAsAttribute(Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("123"), Optional.empty(), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.of("123"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example")));

		p = parse("default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' '" + EXAMPLE_SHA + "'", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.allowsUnsafeInlineStyle());
		assertTrue(p.policy.allowsInlineScript(Optional.of("123"), Optional.empty(), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.of("123"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("456"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("456"), Optional.empty()));
		assertTrue(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example")));
		assertFalse(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example2"), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example2")));

		p = parse("default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' '" + EXAMPLE_SHA + "'; script-src 'none';", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.policy.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse(p.allowsUnsafeInlineStyle());

		assertFalse(p.policy.allowsInlineScript(Optional.of("123"), Optional.empty(), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.of("123"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("456"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("456"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example")));
		assertFalse(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example2"), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example2")));

		p = parse("default-src 'unsafe-inline' 'strict-dynamic' 'nonce-123' '" + EXAMPLE_SHA + "'; style-src 'none';", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.policy.allowsScriptAsAttribute(Optional.of("example")));
		assertFalse(p.allowsUnsafeInlineStyle());
		assertTrue(p.policy.allowsInlineScript(Optional.of("123"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("123"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("456"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("456"), Optional.empty()));
		assertTrue(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example")));
		assertFalse(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example2"), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example2")));


		p = parse("script-src 'unsafe-inline' 'nonce-forscript' 'strict-dynamic'; style-src 'unsafe-inline' 'nonce-forstyle'", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.allowsUnsafeInlineStyle());
		assertTrue(p.policy.allowsInlineScript(Optional.of("forscript"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("forscript"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("forstyle"), Optional.empty(), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.of("forstyle"), Optional.empty()));

		p = parse("script-src-elem 'unsafe-inline' 'nonce-forscript' 'strict-dynamic'; style-src-elem 'unsafe-inline' 'nonce-forstyle'", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.allowsUnsafeInlineStyle());
		assertTrue(p.policy.allowsInlineScript(Optional.of("forscript"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("forscript"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("forstyle"), Optional.empty(), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.of("forstyle"), Optional.empty()));

		Policy policy = parse("default-src 'none'; script-src 'nonce-asdf' 'strict-dynamic'");
		assertTrue(policy.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.of(false)));
		assertTrue(policy.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(false), Optional.empty()));
		assertFalse(policy.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.of(true)));
		assertFalse(policy.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(true), Optional.empty()));
	}


	@Test
	public void testHashAndNonceInvalidateUnsafeInline() {
		PolicyInOrigin p;

		p = parse("default-src 'unsafe-inline' 'nonce-123' ", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.allowsUnsafeInlineStyle());
		assertTrue(p.policy.allowsInlineScript(Optional.of("123"), Optional.empty(), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.of("123"), Optional.empty()));
		assertFalse(p.policy.allowsInlineScript(Optional.of("456"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("456"), Optional.empty()));

		p = parse("default-src 'unsafe-inline' '" + EXAMPLE_SHA + "' ", "http://example.com");
		assertFalse(p.allowsUnsafeInlineScript());
		assertFalse(p.allowsUnsafeInlineStyle());
		assertFalse(p.policy.allowsInlineScript(Optional.of("123"), Optional.empty(), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.of("123"), Optional.empty()));
		assertTrue(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example"), Optional.empty()));
		assertTrue(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example")));
		assertFalse(p.policy.allowsInlineScript(Optional.empty(), Optional.of("example2"), Optional.empty()));
		assertFalse(p.policy.allowsInlineStyle(Optional.empty(), Optional.of("example2")));
	}


	@Test
	public void testWildcards() {
		PolicyInOrigin p;

		p = parse("script-src *", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB chagned
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("script-src *", "applewebdata://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("applewebdata://resource").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("somethingelse://resource").orElse(null)));

		p = parse("script-src *", "file://resource");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("file://anotherresource").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("applewebdata://resource").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("somethingelse://resource").orElse(null)));

		p = parse("script-src *", GUID.parseGUID("data:").orElse(null));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertTrue(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("somethingelse://resource").orElse(null)));

		p = parse("script-src http://*", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("style-src *:80", "http://example.com");
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("style-src *:80", "https://example.com");
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("style-src *:80", "ftp://example.com");
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("img-src ftp://*", "http://example.com");
		assertFalse(p.allowsImageFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsImageFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsImageFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsImageFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsImageFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("style-src *:*", "http://example.com");
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("style-src http://*:*", "http://example.com");
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("style-src ftp://*:*", "http://example.com");
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsStyleFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsStyleFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsStyleFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("img-src */path", "http://example.com");
		assertFalse(p.allowsImageFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsImageFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsImageFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsImageFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsImageFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("script-src *.example.com", "http://example.com");
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.b.example.com/c/d").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://a.b.example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://www.example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://www.EXAMPLE.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsScriptFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("font-src *", "http://example.com");
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsFontFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsFontFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsFontFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("font-src http://*", "http://example.com");
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsFontFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsFontFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("font-src *.example.com", "http://example.com");
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://a.b.example.com/c/d").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://a.b.example.com").orElse(null)));
		assertTrue(p.allowsFontFromSource(URI.parseURI("http://www.example.com").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("http://com").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsFontFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsFontFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsFontFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("object-src *", "http://example.com");
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsObjectFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsObjectFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsObjectFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("object-src http://*", "http://example.com");
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsObjectFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsObjectFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("object-src *.example.com", "http://example.com");
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://a.b.example.com/c/d").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://a.b.example.com").orElse(null)));
		assertTrue(p.allowsObjectFromSource(URI.parseURI("http://www.example.com").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("http://com").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsObjectFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsObjectFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsObjectFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("media-src *", "http://example.com");
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsMediaFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsMediaFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsMediaFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("media-src http://*", "http://example.com");
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsMediaFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsMediaFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("media-src *.example.com", "http://example.com");
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://a.b.example.com/c/d").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://a.b.example.com").orElse(null)));
		assertTrue(p.allowsMediaFromSource(URI.parseURI("http://www.example.com").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("http://com").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsMediaFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsMediaFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsMediaFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("manifest-src *", "http://example.com");
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("ws://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsManifestFromSource(URI.parseURI("wss://example.com/PATH").orElse(null))); // NB changed
		assertFalse(p.allowsManifestFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsManifestFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("manifest-src http://*", "http://example.com");
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("https://example.com").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("http://example.com:81").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("ftp://example.com").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("ftp://example.com:80").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com/path").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://example.com/PATH").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsManifestFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsManifestFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));

		p = parse("manifest-src *.example.com", "http://example.com");
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://a.b.example.com/c/d").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://a.b.example.com").orElse(null)));
		assertTrue(p.allowsManifestFromSource(URI.parseURI("http://www.example.com").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("http://com").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("ws://example.com/PATH").orElse(null)));
		assertFalse(p.allowsManifestFromSource(URI.parseURI("wss://example.com/PATH").orElse(null)));
		assertFalse(p.allowsManifestFromSource(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsManifestFromSource(GUID.parseGUID("custom.scheme:").orElse(null)));
	}

	@Test
	public void testAllowsChild() {
		PolicyInOrigin p;
		
		p = parse("default-src 'none'; child-src 'self'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null))); // NB changed
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse("child-src 'none'; default-src 'self'", "http://example.com");
		assertFalse(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null))); // NB changed
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse("default-src 'self'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse("child-src 'self'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse("child-src 'self'; default-src 'none'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		// worker-src falls back to child-src then script-src then default-src, frame-src falls back to child-src then default-src immediately
		p = parse("script-src 'self'; default-src 'none'", "http://example.com");
		assertFalse(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
	}

	@Test
	public void testAllowsWorker() {
		PolicyInOrigin p;

		p = parse("default-src 'none'; script-src 'self'", "http://example.com");
		assertFalse(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse("script-src 'none'; worker-src 'self'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertFalse(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse(" default-src 'self'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));

		p = parse(" script-src 'self'", "http://example.com");
		assertTrue(p.allowsFrameFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsWorkerFromSource(URI.parseURI("http://example.com").orElse(null)));
		assertTrue(p.allowsScriptFromSource(URI.parseURI("http://example.com").orElse(null)));
	}

	@Test
	public void testAllowNavigationTo() {
		PolicyInOrigin p;

		p = parse("navigate-to blob:", "http://example.com");
		assertTrue(p.allowsNavigation(GUID.parseGUID("blob:").orElse(null)));
		assertFalse(p.allowsNavigation(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsFormAction(GUID.parseGUID("blob:").orElse(null)));
		assertFalse(p.allowsFormAction(GUID.parseGUID("data:").orElse(null)));

		p = parse("navigate-to blob:; form-action data:", "http://example.com");
		assertTrue(p.allowsNavigation(GUID.parseGUID("blob:").orElse(null)));
		assertFalse(p.allowsNavigation(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsFormAction(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsFormAction(GUID.parseGUID("blob:").orElse(null)));

		p = parse("form-action data:", "http://example.com");
		assertTrue(p.allowsNavigation(GUID.parseGUID("blob:").orElse(null)));
		assertTrue(p.allowsNavigation(GUID.parseGUID("data:").orElse(null)));
		assertTrue(p.allowsFormAction(GUID.parseGUID("data:").orElse(null)));
		assertFalse(p.allowsFormAction(GUID.parseGUID("blob:").orElse(null)));


		p = parse("navigate-to a", "http://example.com");
		assertTrue(p.allowsNavigation(URI.parseURI("http://a").orElse(null)));
		assertFalse(p.allowsNavigation(URI.parseURI("http://b").orElse(null)));
		assertTrue(p.allowsFormAction(URI.parseURI("http://a").orElse(null)));
		assertFalse(p.allowsFormAction(URI.parseURI("http://b").orElse(null)));

		p = parse("navigate-to a; form-action b", "http://example.com");
		assertTrue(p.allowsNavigation(URI.parseURI("http://a").orElse(null)));
		assertFalse(p.allowsNavigation(URI.parseURI("http://b").orElse(null)));
		assertTrue(p.allowsFormAction(URI.parseURI("http://b").orElse(null)));
		assertFalse(p.allowsFormAction(URI.parseURI("http://a").orElse(null)));

		p = parse("form-action a", "http://example.com");
		assertTrue(p.allowsNavigation(URI.parseURI("http://a").orElse(null)));
		assertTrue(p.allowsNavigation(URI.parseURI("http://b").orElse(null)));
		assertTrue(p.allowsFormAction(URI.parseURI("http://a").orElse(null)));
		assertFalse(p.allowsFormAction(URI.parseURI("http://b").orElse(null)));
	}

	@Test
	public void testNavigateToWithRedirects() {
		Policy p;

		// If 'unsafe-allow-redirects' is absent, the post-redirect URL does not matter regardless of whether there is a redirect
		p = parse("navigate-to http://example.com");
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(false), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(false), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(false), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(false), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(true), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(true), Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));


		p = parse("navigate-to http://example.com 'unsafe-allow-redirects'");

		// If the user doesn't know if there's a redirect, or explicitly says there was one, and does not supply post-redirect URL, we have to assume it would be blocked after redirect
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));

		// If the user doesn't know if there's a redirect, or explicitly says there was not one, and does not supply pre-redirect URL, we have to assume it would be blocked before redirect
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.empty(), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.empty(), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.empty(), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(false), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(false), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(false), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));

		// If the user doesn't know if there was a redirect, but both pre- and post-redirect URLs are allowed, it's allowed
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.empty(), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.empty(), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/").orElse(null)), Optional.empty(), Optional.of(URI.parseURI("http://example2.com/redirect").orElse(null)), Optional.empty()));

		// If the user does know there was a redirect, pre-redirect URL need not be supplied and does not need to be allowed if it is
		assertTrue(p.allowsNavigation(Optional.empty(), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.empty(), Optional.of(true), Optional.of(URI.parseURI("http://example2.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example2.com/redirect").orElse(null)), Optional.empty()));

		// If the user does know there was a not redirect, post-redirect URL need not be supplied and does not need to be allowed if it is
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com/").orElse(null)), Optional.of(false), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(false), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(false), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(false), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsNavigation(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(false), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertFalse(p.allowsNavigation(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(false), Optional.of(URI.parseURI("http://example2.com/redirect").orElse(null)), Optional.empty()));


		// 'unsafe-allow-redirects' works in 'navigate-to' and not in 'form-action', but applies to forms if 'form-action' is not present
		// The interaction with form-action is weird, but appears to match the spec
		// https://github.com/w3c/webappsec-csp/issues/428
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.of(URI.parseURI("http://example.com/redirect").orElse(null)), Optional.empty()));

		p = parse("form-action http://example.com 'unsafe-allow-redirects'");
		assertTrue(p.allowsNavigation(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com/2").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.of(URI.parseURI("http://example2.com/").orElse(null)), Optional.of(true), Optional.empty(), Optional.empty()));
	}

	@Test
	public void testJavascriptUrl() {
		Policy p;

		p = parse("");
		assertTrue(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));

		p = parse("script-src 'none'");
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));

		p = parse("navigate-to 'none'");
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));

		p = parse("navigate-to javascript:");
		assertTrue(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));

		// 'javascript:' does not govern navigation to javascript: uris
		p = parse("script-src javascript:; navigate-to javascript:");
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));

		p = parse("script-src 'unsafe-hashes' '" + EXAMPLE_SHA + "'; navigate-to javascript:");
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.of("example"), Optional.empty()));

		// the script-src check can pass when the hash is of "javascript:example"
		p = parse("script-src 'unsafe-hashes' 'sha512-AgTbqERrVKA+jazQLvvB8g0pWNNYc1VL0GJSzvyQ4VbyYtqzfdKcLMZ5/PsaUhCckcWvyqUrqJ3IBxCsTi7XjQ=='; navigate-to javascript:");
		assertTrue(p.allowsJavascriptUrlNavigation(Optional.of("example"), Optional.empty()));
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.of("example2"), Optional.empty()));

		// 'unsafe-hashes' must be present to allow hashes
		p = parse("script-src 'sha512-AgTbqERrVKA+jazQLvvB8g0pWNNYc1VL0GJSzvyQ4VbyYtqzfdKcLMZ5/PsaUhCckcWvyqUrqJ3IBxCsTi7XjQ=='; navigate-to javascript:");
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.of("example"), Optional.empty()));
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.of("example2"), Optional.empty()));

		// 'unsafe-inline' also works
		p = parse("script-src 'unsafe-inline'; navigate-to javascript:");
		assertTrue(p.allowsJavascriptUrlNavigation(Optional.of("example"), Optional.empty()));

		// 'strict-dynamic' turns off 'unsafe-line'
		p = parse("script-src 'unsafe-inline' 'strict-dynamic'; navigate-to javascript:");
		assertFalse(p.allowsJavascriptUrlNavigation(Optional.of("example"), Optional.empty()));

		//  'script-src-elem' governs, not 'script-src' or 'script-src-attr'
		p = parse("navigate-to javascript:; script-src 'unsafe-inline'; script-src-attr 'none'");
		assertTrue(p.allowsJavascriptUrlNavigation(Optional.empty(), Optional.empty()));
	}

	@Test
	public void testAllowsEval() {
		Policy p;

		p = parse("");
		assertTrue(p.allowsEval());

		p = parse("default-src 'none'");
		assertFalse(p.allowsEval());

		p = parse("default-src 'unsafe-eval'");
		assertTrue(p.allowsEval());

		p = parse("script-src 'unsafe-eval'");
		assertTrue(p.allowsEval());

		p = parse("script-src 'unsafe-eval'; script-src-elem 'none'; script-src-attr 'none'");
		assertTrue(p.allowsEval());
	}

	@Test
	public void testMissingInfo() {
		Policy p;

		p = parse("default-src *");
		assertFalse(p.allowsFrame(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFrame(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsFrame(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFrame(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.empty()));

		assertFalse(p.allowsConnection(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsConnection(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsConnection(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsConnection(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsFont(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFont(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsFont(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFont(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsImage(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsImage(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsImage(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsImage(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsApplicationManifest(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsApplicationManifest(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsApplicationManifest(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsApplicationManifest(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsMedia(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsMedia(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsMedia(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsMedia(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsObject(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsObject(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsObject(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsObject(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsPrefetch(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsPrefetch(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsPrefetch(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsPrefetch(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		assertFalse(p.allowsWorker(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsWorker(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsWorker(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsWorker(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		p = parse("form-action *");
		assertFalse(p.allowsFormAction(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFormAction(Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsFormAction(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.empty(), Optional.empty(),Optional.of(URI.parseURI("http://example.com").orElse(null))));

		p = parse("frame-ancestors *");
		assertFalse(p.allowsFrameAncestor(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFrameAncestor(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsFrameAncestor(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFrameAncestor(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));

		p = parse("plugin-types a/b", PolicyErrorConsumer.ignored);
		assertFalse(p.allowsPlugin(Optional.empty()));
		assertTrue(p.allowsPlugin(Optional.of(MediaType.parseMediaType("a/b").get())));

		p = parse("default-src example.com");
		assertFalse(p.allowsFrame(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFrame(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFrame(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.empty()));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertTrue(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.of(URI.parseURI("applewebdata://example.com").orElse(null))));

		p = parse("default-src 'self'");
		assertFalse(p.allowsFrame(Optional.empty(), Optional.empty()));
		assertFalse(p.allowsFrame(Optional.empty(), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("http://example.com").orElse(null)), Optional.empty()));
		assertTrue(p.allowsFrame(Optional.of(URI.parseURI("http://example.com/foo").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.empty()));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.of(URI.parseURI("http://example.com").orElse(null))));
		assertFalse(p.allowsFrame(Optional.of(URI.parseURI("applewebdata://example.com").orElse(null)), Optional.of(URI.parseURI("applewebdata://example.com").orElse(null))));
	}

	@Test
	public void testMissingDirectives() {
		Policy p;

		p = parse("");
		assertTrue(p.allowsFrame(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsConnection(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsFont(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsImage(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsApplicationManifest(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsMedia(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsObject(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsPrefetch(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsWorker(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsFormAction(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));

		assertTrue(p.allowsNavigation(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));

		assertTrue(p.allowsFrameAncestor(Optional.empty(), Optional.empty()));

		assertTrue(p.allowsPlugin(Optional.empty()));
	}

	@Test
	public void testSandbox() {
		Policy p;

		p = parse("sandbox");

		assertFalse(p.allowsScriptAsAttribute(Optional.empty()));
		assertFalse(p.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty()));
		assertFalse(p.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));

		assertTrue(p.allowsStyleAsAttribute(Optional.empty()));
		assertTrue(p.allowsInlineStyle(Optional.empty(), Optional.empty()));
		assertTrue(p.allowsExternalStyle(Optional.empty(), Optional.empty(), Optional.empty()));

		assertFalse(p.allowsFormAction(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));


		p = parse("sandbox allow-forms");

		assertTrue(p.allowsFormAction(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));


		p = parse("sandbox allow-scripts");

		assertTrue(p.allowsScriptAsAttribute(Optional.empty()));
		assertTrue(p.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty()));
		assertTrue(p.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
	}



	private Policy parse(String policy) {
		return Policy.parseSerializedCSP(policy, throwIfPolicyError);
	}

	private Policy parse(String policy, PolicyErrorConsumer errorConsumer) {
		return Policy.parseSerializedCSP(policy, errorConsumer);
	}

	private PolicyInOrigin parse(String policy, String origin) {
		return new PolicyInOrigin(Policy.parseSerializedCSP(policy, throwIfPolicyError), URI.parseURI(origin).orElse(null));
	}

	private PolicyInOrigin parse(String policy, URLWithScheme origin) {
		return new PolicyInOrigin(Policy.parseSerializedCSP(policy, throwIfPolicyError), origin);
	}

	private PolicyInOrigin parse(String policy, URLWithScheme origin, PolicyErrorConsumer errorConsumer) {
		return new PolicyInOrigin(Policy.parseSerializedCSP(policy, errorConsumer), origin);
	}
}
