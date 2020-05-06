package com.shapesecurity.salvation2;

import com.shapesecurity.salvation2.Directives.FrameAncestorsDirective;
import com.shapesecurity.salvation2.Directives.PluginTypesDirective;
import com.shapesecurity.salvation2.Directives.ReportUriDirective;
import com.shapesecurity.salvation2.Directives.SandboxDirective;
import com.shapesecurity.salvation2.Directives.SourceExpressionDirective;
import com.shapesecurity.salvation2.Values.Hash;
import com.shapesecurity.salvation2.Values.Host;
import com.shapesecurity.salvation2.Values.MediaType;
import com.shapesecurity.salvation2.Values.Nonce;
import com.shapesecurity.salvation2.Values.RFC7230Token;
import com.shapesecurity.salvation2.Values.Scheme;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HighLevelPolicyManipulationTest extends TestBase {
	private class SourceDirectiveKind {
		final String repr;
		final Function<Policy, SourceExpressionDirective> get;

		private SourceDirectiveKind(String repr, Function<Policy, SourceExpressionDirective> get) {
			this.repr = repr;
			this.get = get;
		}
	}

	/*
// TODO we'll need more tests for using the generic parser for schemes, hosts, nonces, hashes
// and specific cases for their parsers

\			 'http:'
 'FILE:'
 'example.com'
	case-insensitivity of hosts (maybe)
	default port thing
 'example.com/foo'
	case-sensitivity of paths
 'nonce-asdf'
	duplicate nonce
	non-base64 nonce
 hash
	duplicate hash
	unrecognized hash
	hash which is not base64
	hash whose length is inappropriate for its algorithm

\			 not-a-host-source
 @
	case-sensitivity of these

 */

	@Test
	public void testSourceExpressionDirectives() {
		inTurkey(() -> {
			List<SourceDirectiveKind> directives = new ArrayList<>();
			directives.add(new SourceDirectiveKind(
				"base-uri",
				p -> p.baseUri().get()
			));
			directives.add(new SourceDirectiveKind(
				"form-action",
				p -> p.formAction().get()
			));
			directives.add(new SourceDirectiveKind(
				"navigate-to",
				p -> p.navigateTo().get()
			));
			for (FetchDirectiveKind kind : FetchDirectiveKind.values()) {
				directives.add(new SourceDirectiveKind(kind.repr, (p) -> p.getFetchDirective(kind).get()));
			}

			for (SourceDirectiveKind kind : directives) {
				String none = "'NoNe'";
				Policy p = Policy.parseSerializedCSP(kind.repr + " " + none, throwIfPolicyError);
				SourceExpressionDirective d = kind.get.apply(p);


				ArrayList<Supplier<Boolean>> assertions = new ArrayList<>();

				Runnable assertAll = () -> {
					for (Supplier<Boolean> assertion : assertions) {
						assertTrue(assertion.get());
					}
				};

				Supplier<Boolean> notStar = () -> !d.star();
				assertions.add(notStar);

				Supplier<Boolean> notSelf = () -> !d.self();
				assertions.add(notSelf);

				Supplier<Boolean> schemesIsEmpty = () -> d.getSchemes().isEmpty();
				assertions.add(schemesIsEmpty);

				Supplier<Boolean> hostsIsEmpty = () -> d.getHosts().isEmpty();
				assertions.add(hostsIsEmpty);

				Supplier<Boolean> notUnsafeInline = () -> !d.unsafeInline();
				assertions.add(notUnsafeInline);

				Supplier<Boolean> notUnsafeEval = () -> !d.unsafeEval();
				assertions.add(notUnsafeEval);

				Supplier<Boolean> notStrictDynamic = () -> !d.strictDynamic();
				assertions.add(notStrictDynamic);

				Supplier<Boolean> notUnsafeHashes = () -> !d.unsafeHashes();
				assertions.add(notUnsafeHashes);

				Supplier<Boolean> notReportSample = () -> !d.reportSample();
				assertions.add(notReportSample);

				Supplier<Boolean> notUnsafeAllowRedirects = () -> !d.unsafeAllowRedirects();
				assertions.add(notUnsafeAllowRedirects);

				Supplier<Boolean> noncesIsEmpty = () -> d.getNonces().isEmpty();
				assertions.add(noncesIsEmpty);

				Supplier<Boolean> hashesIsEmpty = () -> d.getHashes().isEmpty();
				assertions.add(hashesIsEmpty);


				// 'none'
				assertAll.run();

				// casing of 'none' is preserved when no manipulation occurs
				assertEquals(kind.repr + " " + none, p.toString());


				// 'self'
				d.setSelf(true);
				assertions.remove(notSelf);
				assertAll.run();
				assertTrue(d.self());
				assertEquals(kind.repr + " 'self'", p.toString());

				d.setSelf(true);
				assertAll.run();
				assertTrue(d.self());
				assertEquals(kind.repr + " 'self'", p.toString());

				d.setSelf(false);
				assertions.add(notSelf);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setSelf(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// *
				d.setStar(true);
				assertions.remove(notStar);
				assertAll.run();
				assertTrue(d.star());
				assertEquals(kind.repr + " *", p.toString());

				d.setStar(true);
				assertAll.run();
				assertTrue(d.star());
				assertEquals(kind.repr + " *", p.toString());

				d.setStar(false);
				assertions.add(notStar);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setStar(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.addHost(Host.parseHost("*").get(), throwIfManipulationError);
				assertions.remove(notStar);
				assertAll.run();
				assertTrue(d.star());
				assertEquals(kind.repr + " *", p.toString());

				assertTrue(d.removeHost(Host.parseHost("*").get()));
				assertFalse(d.removeHost(Host.parseHost("*").get()));
				assertions.add(notStar);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// 'unsafe-inline'
				d.setUnsafeInline(true);
				assertions.remove(notUnsafeInline);
				assertAll.run();
				assertTrue(d.unsafeInline());
				assertEquals(kind.repr + " 'unsafe-inline'", p.toString());

				d.setUnsafeInline(true);
				assertAll.run();
				assertTrue(d.unsafeInline());
				assertEquals(kind.repr + " 'unsafe-inline'", p.toString());

				d.setUnsafeInline(false);
				assertions.add(notUnsafeInline);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setUnsafeInline(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// 'unsafe-eval'
				d.setUnsafeEval(true);
				assertions.remove(notUnsafeEval);
				assertAll.run();
				assertTrue(d.unsafeEval());
				assertEquals(kind.repr + " 'unsafe-eval'", p.toString());

				d.setUnsafeEval(true);
				assertAll.run();
				assertTrue(d.unsafeEval());
				assertEquals(kind.repr + " 'unsafe-eval'", p.toString());

				d.setUnsafeEval(false);
				assertions.add(notUnsafeEval);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setUnsafeEval(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// 'strict-dynamic'
				d.setStrictDynamic(true);
				assertions.remove(notStrictDynamic);
				assertAll.run();
				assertTrue(d.strictDynamic());
				assertEquals(kind.repr + " 'strict-dynamic'", p.toString());

				d.setStrictDynamic(true);
				assertAll.run();
				assertTrue(d.strictDynamic());
				assertEquals(kind.repr + " 'strict-dynamic'", p.toString());

				d.setStrictDynamic(false);
				assertions.add(notStrictDynamic);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setStrictDynamic(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// 'unsafe-hashes'
				d.setUnsafeHashes(true);
				assertions.remove(notUnsafeHashes);
				assertAll.run();
				assertTrue(d.unsafeHashes());
				assertEquals(kind.repr + " 'unsafe-hashes'", p.toString());

				d.setUnsafeHashes(true);
				assertAll.run();
				assertTrue(d.unsafeHashes());
				assertEquals(kind.repr + " 'unsafe-hashes'", p.toString());

				d.setUnsafeHashes(false);
				assertions.add(notUnsafeHashes);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setUnsafeHashes(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// 'report-sample'
				d.setReportSample(true);
				assertions.remove(notReportSample);
				assertAll.run();
				assertTrue(d.reportSample());
				assertEquals(kind.repr + " 'report-sample'", p.toString());

				d.setReportSample(true);
				assertAll.run();
				assertTrue(d.reportSample());
				assertEquals(kind.repr + " 'report-sample'", p.toString());

				d.setReportSample(false);
				assertions.add(notReportSample);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setReportSample(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// 'unsafe-allow-redirects'
				d.setUnsafeAllowRedirects(true);
				assertions.remove(notUnsafeAllowRedirects);
				assertAll.run();
				assertTrue(d.unsafeAllowRedirects());
				assertEquals(kind.repr + " 'unsafe-allow-redirects'", p.toString());

				d.setUnsafeAllowRedirects(true);
				assertAll.run();
				assertTrue(d.unsafeAllowRedirects());
				assertEquals(kind.repr + " 'unsafe-allow-redirects'", p.toString());

				d.setUnsafeAllowRedirects(false);
				assertions.add(notUnsafeAllowRedirects);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());

				d.setUnsafeAllowRedirects(false);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// schemes
				d.addScheme(scheme("FILE:"), throwIfManipulationError);
				assertions.remove(schemesIsEmpty);
				assertAll.run();
				assertEquals(schemes("file:"), d.getSchemes());
				assertEquals(kind.repr + " file:", p.toString());

				d.addScheme(scheme("wip:"), throwIfManipulationError);
				assertAll.run();
				assertEquals(schemes("file:", "wip:"), d.getSchemes());
				assertEquals(kind.repr + " file: wip:", p.toString());

				d.addScheme(scheme("file:"), manipulationErrorConsumer);
				assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate scheme file:"));
				assertAll.run();
				assertEquals(schemes("file:", "wip:"), d.getSchemes());
				assertEquals(kind.repr + " file: wip:", p.toString());

				assertTrue(d.removeScheme(scheme("file:")));
				assertFalse(d.removeScheme(scheme("file:")));
				assertAll.run();
				assertEquals(schemes("wip:"), d.getSchemes());
				assertEquals(kind.repr + " wip:", p.toString());

				assertTrue(d.removeScheme(scheme("WIP:")));
				assertFalse(d.removeScheme(scheme("WIP:")));
				assertions.add(schemesIsEmpty);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// hosts
				d.addHost(host("example.com"), throwIfManipulationError);
				assertions.remove(hostsIsEmpty);
				assertAll.run();
				assertEquals(hosts("example.com"), d.getHosts());
				assertEquals(kind.repr + " example.com", p.toString());

				d.addHost(host("2.example.com"), throwIfManipulationError);
				assertAll.run();
				assertEquals(hosts("example.com", "2.example.com"), d.getHosts());
				assertEquals(kind.repr + " example.com 2.example.com", p.toString());

				d.addHost(host("EXAMPLE.COM"), manipulationErrorConsumer);
				assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate host example.com"));
				assertAll.run();
				assertEquals(hosts("example.com", "2.example.com"), d.getHosts());
				assertEquals(kind.repr + " example.com 2.example.com", p.toString());

				assertTrue(d.removeHost(host("example.com")));
				assertFalse(d.removeHost(host("example.com")));
				assertAll.run();
				assertEquals(hosts("2.example.com"), d.getHosts());
				assertEquals(kind.repr + " 2.example.com", p.toString());

				assertTrue(d.removeHost(host("2.example.com")));
				assertFalse(d.removeHost(host("2.example.com")));
				assertions.add(schemesIsEmpty);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// nonces
				d.addNonce(nonce("'nonce-asdf'"), throwIfManipulationError);
				assertions.remove(noncesIsEmpty);
				assertAll.run();
				assertEquals(nonces("'nonce-asdf'"), d.getNonces());
				assertEquals(kind.repr + " 'nonce-asdf'", p.toString());

				d.addNonce(nonce("'nonce-ASDF'"), throwIfManipulationError);
				assertAll.run();
				assertEquals(nonces("'nonce-asdf'", "'nonce-ASDF'"), d.getNonces());
				assertEquals(kind.repr + " 'nonce-asdf' 'nonce-ASDF'", p.toString());

				d.addNonce(nonce("'NONCE-asdf'"), manipulationErrorConsumer);
				assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate nonce 'nonce-asdf'"));
				assertAll.run();
				assertEquals(nonces("'nonce-asdf'", "'nonce-ASDF'"), d.getNonces());
				assertEquals(kind.repr + " 'nonce-asdf' 'nonce-ASDF'", p.toString());

				assertTrue(d.removeNonce(nonce("'nonce-asdf'")));
				assertFalse(d.removeNonce(nonce("'nonce-asdf'")));
				assertAll.run();
				assertEquals(nonces("'nonce-ASDF'"), d.getNonces());
				assertEquals(kind.repr + " 'nonce-ASDF'", p.toString());

				assertTrue(d.removeNonce(nonce("'nonce-ASDF'")));
				assertFalse(d.removeNonce(nonce("'nonce-ASDF'")));
				assertions.add(noncesIsEmpty);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());


				// hashes
				d.addHash(hash("'sha256-asdf'"), manipulationErrorConsumer);
				assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Wrong length for sha256: expected 44, got 4"));
				assertions.remove(hashesIsEmpty);
				assertAll.run();
				assertEquals(hashes("'sha256-asdf'"), d.getHashes());
				assertEquals(kind.repr + " 'sha256-asdf'", p.toString());

				d.addHash(hash("'sha256-ASDF'"), manipulationErrorConsumer);
				assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Wrong length for sha256: expected 44, got 4"));
				assertAll.run();
				assertEquals(hashes("'sha256-asdf'", "'sha256-ASDF'"), d.getHashes());
				assertEquals(kind.repr + " 'sha256-asdf' 'sha256-ASDF'", p.toString());

				d.addHash(hash("'SHA256-asdf'"), manipulationErrorConsumer);
				assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate hash 'sha256-asdf'"));
				assertAll.run();
				assertEquals(hashes("'sha256-asdf'", "'sha256-ASDF'"), d.getHashes());
				assertEquals(kind.repr + " 'sha256-asdf' 'sha256-ASDF'", p.toString());

				assertTrue(d.removeHash(hash("'sha256-asdf'")));
				assertFalse(d.removeHash(hash("'sha256-asdf'")));
				assertAll.run();
				assertEquals(hashes("'sha256-ASDF'"), d.getHashes());
				assertEquals(kind.repr + " 'sha256-ASDF'", p.toString());

				assertTrue(d.removeHash(hash("'sha256-ASDF'")));
				assertFalse(d.removeHash(hash("'sha256-ASDF'")));
				assertions.add(noncesIsEmpty);
				assertAll.run();
				assertEquals(kind.repr + " 'none'", p.toString());
			}
		});
	}

	@Test
	public void testFrameAncestorsDirective() {
		inTurkey(() -> {
			String none = "'NoNe'";
			Policy p = Policy.parseSerializedCSP("frame-ancestors " + none, throwIfPolicyError);
			assertTrue(p.frameAncestors().isPresent());
			FrameAncestorsDirective d = p.frameAncestors().get();

			ArrayList<Supplier<Boolean>> assertions = new ArrayList<>();

			Runnable assertAll = () -> {
				for (Supplier<Boolean> assertion : assertions) {
					assertTrue(assertion.get());
				}
			};

			Supplier<Boolean> notStar = () -> !d.star();
			assertions.add(notStar);

			Supplier<Boolean> notSelf = () -> !d.self();
			assertions.add(notSelf);

			Supplier<Boolean> schemesIsEmpty = () -> d.getSchemes().isEmpty();
			assertions.add(schemesIsEmpty);

			Supplier<Boolean> hostsIsEmpty = () -> d.getHosts().isEmpty();
			assertions.add(hostsIsEmpty);


			// 'none'
			assertAll.run();

			// casing of 'none' is preserved when no manipulation occurs
			assertEquals("frame-ancestors " + none, p.toString());


			// 'self'
			d.setSelf(true);
			assertions.remove(notSelf);
			assertAll.run();
			assertTrue(d.self());
			assertEquals("frame-ancestors 'self'", p.toString());

			d.setSelf(false);
			assertions.add(notSelf);
			assertAll.run();
			assertEquals("frame-ancestors 'none'", p.toString());


			// *
			// TODO remove this, it should be subsumed by hash
			d.setStar(true);
			assertions.remove(notStar);
			assertAll.run();
			assertTrue(d.star());
			assertEquals("frame-ancestors *", p.toString());

			d.setStar(false);
			assertions.add(notStar);
			assertAll.run();
			assertEquals("frame-ancestors 'none'", p.toString());


			// schemes
			d.addScheme(scheme("FILE:"), throwIfManipulationError);
			assertions.remove(schemesIsEmpty);
			assertAll.run();
			assertEquals(schemes("file:"), d.getSchemes());
			assertEquals("frame-ancestors file:", p.toString());

			d.addScheme(scheme("wip:"), throwIfManipulationError);
			assertAll.run();
			assertEquals(schemes("file:", "wip:"), d.getSchemes());
			assertEquals("frame-ancestors file: wip:", p.toString());

			d.addScheme(scheme("file:"), manipulationErrorConsumer);
			assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate scheme file:"));
			assertAll.run();
			assertEquals(schemes("file:", "wip:"), d.getSchemes());
			assertEquals("frame-ancestors file: wip:", p.toString());

			assertTrue(d.removeScheme(scheme("file:")));
			assertFalse(d.removeScheme(scheme("file:")));
			assertAll.run();
			assertEquals(schemes("wip:"), d.getSchemes());
			assertEquals("frame-ancestors wip:", p.toString());

			assertTrue(d.removeScheme(scheme("WIP:")));
			assertFalse(d.removeScheme(scheme("WIP:")));
			assertions.add(schemesIsEmpty);
			assertAll.run();
			assertEquals("frame-ancestors 'none'", p.toString());


			// hosts
			d.addHost(host("example.com"), throwIfManipulationError);
			assertions.remove(hostsIsEmpty);
			assertAll.run();
			assertEquals(hosts("example.com"), d.getHosts());
			assertEquals("frame-ancestors example.com", p.toString());

			d.addHost(host("2.example.com"), throwIfManipulationError);
			assertAll.run();
			assertEquals(hosts("example.com", "2.example.com"), d.getHosts());
			assertEquals("frame-ancestors example.com 2.example.com", p.toString());

			d.addHost(host("EXAMPLE.COM"), manipulationErrorConsumer);
			assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate host example.com"));
			assertAll.run();
			assertEquals(hosts("example.com", "2.example.com"), d.getHosts());
			assertEquals("frame-ancestors example.com 2.example.com", p.toString());

			assertTrue(d.removeHost(host("example.com")));
			assertFalse(d.removeHost(host("example.com")));
			assertAll.run();
			assertEquals(hosts("2.example.com"), d.getHosts());
			assertEquals("frame-ancestors 2.example.com", p.toString());

			assertTrue(d.removeHost(host("2.example.com")));
			assertFalse(d.removeHost(host("2.example.com")));
			assertions.add(schemesIsEmpty);
			assertAll.run();
			assertEquals("frame-ancestors 'none'", p.toString());
		});
	}

	@Test
	public void testPluginTypesDirective() {
		inTurkey(() -> {
			Policy p = Policy.parseSerializedCSP("plugin-types", throwIfPolicyError);
			PluginTypesDirective d = p.pluginTypes().get();

			assertTrue(d.getMediaTypes().isEmpty());
			assertEquals("plugin-types", p.toString());

			d.addMediaType(mediaType("a/b"), throwIfManipulationError);
			assertEquals(mediaTypes("a/b"), d.getMediaTypes());
			assertEquals("plugin-types a/b", p.toString());

			d.addMediaType(mediaType("a/c"), throwIfManipulationError);
			assertEquals(mediaTypes("a/b", "a/c"), d.getMediaTypes());
			assertEquals("plugin-types a/b a/c", p.toString());

			d.addMediaType(mediaType("a/B"), manipulationErrorConsumer);
			assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate media type a/b"));
			assertEquals(mediaTypes("a/b", "a/c"), d.getMediaTypes());
			assertEquals("plugin-types a/b a/c", p.toString());

			assertTrue(d.removeMediaType(mediaType("a/b")));
			assertFalse(d.removeMediaType(mediaType("a/b")));
			assertEquals(mediaTypes("a/c"), d.getMediaTypes());
			assertEquals("plugin-types a/c", p.toString());

			assertTrue(d.removeMediaType(mediaType("a/c")));
			assertFalse(d.removeMediaType(mediaType("a/c")));
			assertTrue(d.getMediaTypes().isEmpty());
			assertEquals("plugin-types", p.toString());
		});
	}

	@Test
	public void testReportUriDirective() {
		inTurkey(() -> {
			Policy p = Policy.parseSerializedCSP("report-uri http://example.com", Policy.PolicyErrorConsumer.ignored);
			ReportUriDirective d = p.reportUri().get();

			assertEquals(Arrays.asList("http://example.com"), d.getUris());
			assertEquals("report-uri http://example.com", p.toString());

			d.addUri("http://2.example.com", throwIfManipulationError);
			assertEquals(Arrays.asList("http://example.com", "http://2.example.com"), d.getUris());
			assertEquals("report-uri http://example.com http://2.example.com", p.toString());

			d.addUri("http://example.com", manipulationErrorConsumer);
			assertErrors(e(Directive.ManipulationErrorConsumer.Severity.Info, "Duplicate report-to URI; are you sure you intend to get multiple copies of each report?"));
			assertEquals(Arrays.asList("http://example.com", "http://2.example.com", "http://example.com"), d.getUris());
			assertEquals("report-uri http://example.com http://2.example.com http://example.com", p.toString());

			assertTrue(d.removeUri("http://example.com"));
			assertFalse(d.removeUri("http://example.com"));
			assertEquals(Arrays.asList("http://2.example.com"), d.getUris());
			assertEquals("report-uri http://2.example.com", p.toString());
		});
	}

	@Test
	public void testSandboxDirective() {
		inTurkey(() -> {
			Policy p = Policy.parseSerializedCSP("sandbox", throwIfPolicyError);
			SandboxDirective d = p.sandbox().get();

			assertFalse(d.allowDownloads());
			assertFalse(d.allowForms());
			assertFalse(d.allowModals());
			assertFalse(d.allowOrientationLock());
			assertFalse(d.allowPointerLock());
			assertFalse(d.allowPopups());
			assertFalse(d.allowPopupsToEscapeSandbox());
			assertFalse(d.allowPresentation());
			assertFalse(d.allowSameOrigin());
			assertFalse(d.allowScripts());
			assertFalse(d.allowStorageAccessByUserActivation());
			assertFalse(d.allowTopNavigation());
			assertFalse(d.allowTopNavigationByUserActivation());
			assertEquals("sandbox", p.toString());




			d.setAllowDownloads(true);
			assertTrue(d.allowDownloads());
			assertEquals("sandbox allow-downloads", p.toString());

			d.setAllowDownloads(true);
			assertTrue(d.allowDownloads());
			assertEquals("sandbox allow-downloads", p.toString());

			d.setAllowForms(true);
			assertTrue(d.allowForms());
			assertEquals("sandbox allow-downloads allow-forms", p.toString());

			d.setAllowForms(true);
			assertTrue(d.allowForms());
			assertEquals("sandbox allow-downloads allow-forms", p.toString());

			d.setAllowModals(true);
			assertTrue(d.allowModals());
			assertEquals("sandbox allow-downloads allow-forms allow-modals", p.toString());

			d.setAllowModals(true);
			assertTrue(d.allowModals());
			assertEquals("sandbox allow-downloads allow-forms allow-modals", p.toString());

			d.setAllowOrientationLock(true);
			assertTrue(d.allowOrientationLock());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock", p.toString());

			d.setAllowOrientationLock(true);
			assertTrue(d.allowOrientationLock());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock", p.toString());

			d.setAllowPointerLock(true);
			assertTrue(d.allowPointerLock());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock", p.toString());

			d.setAllowPointerLock(true);
			assertTrue(d.allowPointerLock());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock", p.toString());

			d.setAllowPopups(true);
			assertTrue(d.allowPopups());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups", p.toString());

			d.setAllowPopups(true);
			assertTrue(d.allowPopups());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups", p.toString());

			d.setAllowPopupsToEscapeSandbox(true);
			assertTrue(d.allowPopupsToEscapeSandbox());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox", p.toString());

			d.setAllowPopupsToEscapeSandbox(true);
			assertTrue(d.allowPopupsToEscapeSandbox());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox", p.toString());

			d.setAllowPresentation(true);
			assertTrue(d.allowPresentation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation", p.toString());

			d.setAllowPresentation(true);
			assertTrue(d.allowPresentation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation", p.toString());

			d.setAllowSameOrigin(true);
			assertTrue(d.allowSameOrigin());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin", p.toString());

			d.setAllowSameOrigin(true);
			assertTrue(d.allowSameOrigin());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin", p.toString());

			d.setAllowScripts(true);
			assertTrue(d.allowScripts());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts", p.toString());

			d.setAllowScripts(true);
			assertTrue(d.allowScripts());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts", p.toString());

			d.setAllowStorageAccessByUserActivation(true);
			assertTrue(d.allowStorageAccessByUserActivation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation", p.toString());

			d.setAllowStorageAccessByUserActivation(true);
			assertTrue(d.allowStorageAccessByUserActivation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation", p.toString());

			d.setAllowTopNavigation(true);
			assertTrue(d.allowTopNavigation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation", p.toString());

			d.setAllowTopNavigation(true);
			assertTrue(d.allowTopNavigation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation", p.toString());

			d.setAllowTopNavigationByUserActivation(true);
			assertTrue(d.allowTopNavigationByUserActivation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowTopNavigationByUserActivation(true);
			assertTrue(d.allowTopNavigationByUserActivation());
			assertEquals("sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowDownloads(false);
			assertFalse(d.allowDownloads());
			assertEquals("sandbox allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowDownloads(false);
			assertFalse(d.allowDownloads());
			assertEquals("sandbox allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowForms(false);
			assertFalse(d.allowForms());
			assertEquals("sandbox allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowForms(false);
			assertFalse(d.allowForms());
			assertEquals("sandbox allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowModals(false);
			assertFalse(d.allowModals());
			assertEquals("sandbox allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowModals(false);
			assertFalse(d.allowModals());
			assertEquals("sandbox allow-orientation-lock allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowOrientationLock(false);
			assertFalse(d.allowOrientationLock());
			assertEquals("sandbox allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowOrientationLock(false);
			assertFalse(d.allowOrientationLock());
			assertEquals("sandbox allow-pointer-lock allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPointerLock(false);
			assertFalse(d.allowPointerLock());
			assertEquals("sandbox allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPointerLock(false);
			assertFalse(d.allowPointerLock());
			assertEquals("sandbox allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPopups(false);
			assertFalse(d.allowPopups());
			assertEquals("sandbox allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPopups(false);
			assertFalse(d.allowPopups());
			assertEquals("sandbox allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPopupsToEscapeSandbox(false);
			assertFalse(d.allowPopupsToEscapeSandbox());
			assertEquals("sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPopupsToEscapeSandbox(false);
			assertFalse(d.allowPopupsToEscapeSandbox());
			assertEquals("sandbox allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPresentation(false);
			assertFalse(d.allowPresentation());
			assertEquals("sandbox allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowPresentation(false);
			assertFalse(d.allowPresentation());
			assertEquals("sandbox allow-same-origin allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowSameOrigin(false);
			assertFalse(d.allowSameOrigin());
			assertEquals("sandbox allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowSameOrigin(false);
			assertFalse(d.allowSameOrigin());
			assertEquals("sandbox allow-scripts allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowScripts(false);
			assertFalse(d.allowScripts());
			assertEquals("sandbox allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowScripts(false);
			assertFalse(d.allowScripts());
			assertEquals("sandbox allow-storage-access-by-user-activation allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowStorageAccessByUserActivation(false);
			assertFalse(d.allowStorageAccessByUserActivation());
			assertEquals("sandbox allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowStorageAccessByUserActivation(false);
			assertFalse(d.allowStorageAccessByUserActivation());
			assertEquals("sandbox allow-top-navigation allow-top-navigation-by-user-activation", p.toString());

			d.setAllowTopNavigation(false);
			assertFalse(d.allowTopNavigation());
			assertEquals("sandbox allow-top-navigation-by-user-activation", p.toString());

			d.setAllowTopNavigation(false);
			assertFalse(d.allowTopNavigation());
			assertEquals("sandbox allow-top-navigation-by-user-activation", p.toString());

			d.setAllowTopNavigationByUserActivation(false);
			assertFalse(d.allowTopNavigationByUserActivation());
			assertEquals("sandbox", p.toString());

			d.setAllowTopNavigationByUserActivation(false);
			assertFalse(d.allowTopNavigationByUserActivation());
			assertEquals("sandbox", p.toString());
		});
	}

	@Test
	public void testReportToDirective() {
		Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);

		// Setting creates a directive if none existed
		p.setReportTo(rfc7230Token("a"));
		assertEquals(rfc7230Token("a"), p.reportTo().get());
		assertEquals("report-to a", p.toString());

		// Setting overwrites existing
		p = Policy.parseSerializedCSP("report-to a", Policy.PolicyErrorConsumer.ignored);
		assertEquals(rfc7230Token("a"), p.reportTo().get());
		assertEquals("report-to a", p.toString());

		p.setReportTo(rfc7230Token("b"));
		assertEquals(rfc7230Token("b"), p.reportTo().get());
		assertEquals("report-to b", p.toString());

		// Only the first directive is overwritten
		p = Policy.parseSerializedCSP("report-to a; report-to b", Policy.PolicyErrorConsumer.ignored);
		assertEquals(rfc7230Token("a"), p.reportTo().get());
		assertEquals("report-to a; report-to b", p.toString());

		p.setReportTo(rfc7230Token("c"));
		assertEquals(rfc7230Token("c"), p.reportTo().get());
		assertEquals("report-to c; report-to b", p.toString());

		// Setting to null deletes all directives
		p.setReportTo(null);
		assertFalse(p.reportTo().isPresent());
		assertEquals("", p.toString());

		// Setting to null deletes malformed directives as well
		p = Policy.parseSerializedCSP("report-to a b; report-to; default-src *", Policy.PolicyErrorConsumer.ignored);
		p.setReportTo(null);
		assertFalse(p.reportTo().isPresent());
		assertEquals("default-src *", p.toString());

		// Malformed values are overwritten
		p = Policy.parseSerializedCSP("report-to a b; default-src *", Policy.PolicyErrorConsumer.ignored);
		assertFalse(p.reportTo().isPresent());
		assertEquals("report-to a b; default-src *", p.toString());

		p.setReportTo(rfc7230Token("c"));
		assertEquals(rfc7230Token("c"), p.reportTo().get());
		assertEquals("report-to c; default-src *", p.toString());

		p = Policy.parseSerializedCSP("report-to; default-src *", Policy.PolicyErrorConsumer.ignored);
		assertFalse(p.reportTo().isPresent());
		assertEquals("report-to; default-src *", p.toString());

		p.setReportTo(rfc7230Token("c"));
		assertEquals(rfc7230Token("c"), p.reportTo().get());
		assertEquals("report-to c; default-src *", p.toString());
	}

	@Test
	public void testBooleanDirectives() {
		Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
		assertFalse(p.blockAllMixedContent());
		assertFalse(p.upgradeInsecureRequests());

		p.setBlockAllMixedContent(true);
		assertTrue(p.blockAllMixedContent());
		assertFalse(p.upgradeInsecureRequests());
		assertEquals("block-all-mixed-content", p.toString());

		p.setBlockAllMixedContent(true);
		assertTrue(p.blockAllMixedContent());
		assertFalse(p.upgradeInsecureRequests());
		assertEquals("block-all-mixed-content", p.toString());

		p.setUpgradeInsecureRequests(true);
		assertTrue(p.blockAllMixedContent());
		assertTrue(p.upgradeInsecureRequests());
		assertEquals("block-all-mixed-content; upgrade-insecure-requests", p.toString());

		p.setUpgradeInsecureRequests(true);
		assertTrue(p.blockAllMixedContent());
		assertTrue(p.upgradeInsecureRequests());
		assertEquals("block-all-mixed-content; upgrade-insecure-requests", p.toString());

		p.setBlockAllMixedContent(false);
		assertFalse(p.blockAllMixedContent());
		assertTrue(p.upgradeInsecureRequests());
		assertEquals("upgrade-insecure-requests", p.toString());

		p.setBlockAllMixedContent(false);
		assertFalse(p.blockAllMixedContent());
		assertTrue(p.upgradeInsecureRequests());
		assertEquals("upgrade-insecure-requests", p.toString());

		p.setUpgradeInsecureRequests(false);
		assertFalse(p.blockAllMixedContent());
		assertFalse(p.upgradeInsecureRequests());
		assertEquals("", p.toString());

		p.setUpgradeInsecureRequests(false);
		assertFalse(p.blockAllMixedContent());
		assertFalse(p.upgradeInsecureRequests());
		assertEquals("", p.toString());
	}

	@Test
	public void testWarnings() {
		inTurkey(() -> {
			Policy p = Policy.parseSerializedCSP("default-src *", throwIfPolicyError);
			SourceExpressionDirective d = p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get();

			d.addHost(Host.parseHost("*").get(), manipulationErrorConsumer);
			assertErrors(
					e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate host *")
			);
		});
	}

	private ArrayList<ManipulationError> observedErrors = new ArrayList<>();

	private Directive.ManipulationErrorConsumer manipulationErrorConsumer = (severity, message) -> {
		observedErrors.add(e(severity, message));
	};

	private void assertErrors(ManipulationError... expectedErrors) {
		assertEquals("should have the expected number of errors", expectedErrors.length, observedErrors.size());
		for (int i = 0; i < expectedErrors.length; ++i) {
			assertEquals(expectedErrors[i], observedErrors.get(i));
		}
		observedErrors.clear();
	}


	private Scheme scheme(String scheme) {
		return Scheme.parseScheme(scheme).get();
	}

	private List<Scheme> schemes(String... schemes) {
		ArrayList<Scheme> out = new ArrayList<>(schemes.length);
		for (String scheme : schemes) {
			out.add(scheme(scheme));
		}
		return out;
	}

	private Host host(String host) {
		return Host.parseHost(host).get();
	}

	private List<Host> hosts(String... hosts) {
		ArrayList<Host> out = new ArrayList<>(hosts.length);
		for (String host : hosts) {
			out.add(host(host));
		}
		return out;
	}

	private Nonce nonce(String nonce) {
		return Nonce.parseNonce(nonce).get();
	}

	private List<Nonce> nonces(String... nonces) {
		ArrayList<Nonce> out = new ArrayList<>(nonces.length);
		for (String nonce : nonces) {
			out.add(nonce(nonce));
		}
		return out;
	}

	private Hash hash(String hash) {
		return Hash.parseHash(hash).get();
	}

	private List<Hash> hashes(String... hashes) {
		ArrayList<Hash> out = new ArrayList<>(hashes.length);
		for (String hash : hashes) {
			out.add(hash(hash));
		}
		return out;
	}

	private MediaType mediaType(String mediaType) {
		return MediaType.parseMediaType(mediaType).get();
	}

	private List<MediaType> mediaTypes(String... mediaTypes) {
		ArrayList<MediaType> out = new ArrayList<>(mediaTypes.length);
		for (String mediaType : mediaTypes) {
			out.add(mediaType(mediaType));
		}
		return out;
	}

	private RFC7230Token rfc7230Token(String token) {
		return RFC7230Token.parseRFC7230Token(token).get();
	}

}
