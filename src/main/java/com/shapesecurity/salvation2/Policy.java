package com.shapesecurity.salvation2;

import com.shapesecurity.salvation2.Directives.FrameAncestorsDirective;
import com.shapesecurity.salvation2.Directives.HostSourceDirective;
import com.shapesecurity.salvation2.Directives.PluginTypesDirective;
import com.shapesecurity.salvation2.Directives.ReportUriDirective;
import com.shapesecurity.salvation2.Directives.SandboxDirective;
import com.shapesecurity.salvation2.Directives.SourceExpressionDirective;
import com.shapesecurity.salvation2.URLs.GUID;
import com.shapesecurity.salvation2.URLs.URI;
import com.shapesecurity.salvation2.URLs.URLWithScheme;
import com.shapesecurity.salvation2.Values.Hash;
import com.shapesecurity.salvation2.Values.Host;
import com.shapesecurity.salvation2.Values.MediaType;
import com.shapesecurity.salvation2.Values.RFC7230Token;
import com.shapesecurity.salvation2.Values.Scheme;

import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Policy {
	// Things we don't preserve:
	// - Whitespace
	// - Empty directives or policies (as in `; ;` or `, ,`)
	// Things we do preserve:
	// - Source-expression lists being genuinely empty vs consisting of 'none'
	// - Case (as in lowercase vs uppercase)
	// - Order
	// - Duplicate directives
	// - Unrecognized directives
	// - Values in directives which forbid them
	// - Duplicate values
	// - Unrecognized values

	private List<NamedDirective> directives = new ArrayList<>();

	private SourceExpressionDirective baseUri = null;
	private boolean blockAllMixedContent = false;
	private SourceExpressionDirective formAction = null;

	private FrameAncestorsDirective frameAncestors = null;

	private SourceExpressionDirective navigateTo = null;

	private PluginTypesDirective pluginTypes;

	private RFC7230Token reportTo;

	private ReportUriDirective reportUri;

	private SandboxDirective sandbox = null;
	private boolean upgradeInsecureRequests = false;

	@Nonnull
	private final EnumMap<FetchDirectiveKind, SourceExpressionDirective> fetchDirectives = new EnumMap<>(FetchDirectiveKind.class);

	private Policy() {
		// pass
	}

	// https://w3c.github.io/webappsec-csp/#parse-serialized-policy-list
	@Nonnull
	public static PolicyList parseSerializedCSPList(String serialized, PolicyListErrorConsumer policyListErrorConsumer) {
		// "A serialized CSP list is an ASCII string"
		enforceAscii(serialized);

		List<Policy> policies = new ArrayList<>();

		int[] index = { 0 }; // java's lambdas are dumb
		PolicyErrorConsumer policyErrorConsumer = (Severity severity, String message, int directiveIndex, int valueIndex) -> {
			policyListErrorConsumer.add(severity, message, index[0], directiveIndex, valueIndex);
		};

		// https://infra.spec.whatwg.org/#split-on-commas
		for (String token : serialized.split(",")) {
			Policy policy = parseSerializedCSP(token, policyErrorConsumer);
			if (policy.directives.isEmpty()) {
				++index[0];
				continue;
			}

			policies.add(policy);

			++index[0];
		}
		return new PolicyList(policies);
	}

	// https://w3c.github.io/webappsec-csp/#parse-serialized-policy
	@Nonnull
	public static Policy parseSerializedCSP(String serialized, PolicyErrorConsumer policyErrorConsumer) {
		// "A serialized CSP is an ASCII string", and browsers do in fact reject CSPs which contain non-ASCII characters
		enforceAscii(serialized);
		if (serialized.contains(",")) {
			// This is not quite per spec, but
			throw new IllegalArgumentException("Serialized CSPs cannot contain commas - you may have wanted parseSerializedCSPList");
		}

		int[] index = { 0 }; // java's lambdas are dumb
		Directive.DirectiveErrorConsumer directiveErrorConsumer = (Severity severity, String message, int valueIndex) -> {
			policyErrorConsumer.add(severity, message, index[0], valueIndex);
		};

		Policy policy = new Policy();

		// https://infra.spec.whatwg.org/#strictly-split
		for (String token : serialized.split(";")) {
			String strippedLeadingAndTrailingWhitespace = stripTrailingWhitespace(stripLeadingWhitespace(token));
			if (strippedLeadingAndTrailingWhitespace.isEmpty()) {
				++index[0];
				continue;
			}
			String directiveName = collect(strippedLeadingAndTrailingWhitespace, "[^'" + Constants.WHITESPACE_CHARS + "]+");

			// Note: we do not lowercase directive names or skip duplicates during parsing, to allow round-tripping even invalid policies

			String remainingToken = strippedLeadingAndTrailingWhitespace.substring(directiveName.length());

			if (remainingToken.length() > 0 && !containsLeadingWhitespace(remainingToken)) {
				throw new IllegalArgumentException("directive value requires leading ascii whitespace");
			}

			List<String> directiveValues = Utils.splitOnAsciiWhitespace(remainingToken);

			policy.add(directiveName, directiveValues, directiveErrorConsumer);

			++index[0];
		}

		return policy;
	}


	// Manipulation APIs


	// We do not provide a generic method for updating an existing directive in-place. Just remove the existing one and add it back.
	public Directive add(String name, List<String> values, Directive.DirectiveErrorConsumer directiveErrorConsumer) {
		enforceAscii(name);
		if (Directive.containsNonDirectiveCharacter.test(name)) {
			throw new IllegalArgumentException("directive names must not contain whitespace, ',', or ';'");
		}
		if (name.isEmpty()) {
			throw new IllegalArgumentException("directive names must not be empty");
		}

		boolean wasDupe = false;
		Directive newDirective;
		String lowcaseDirectiveName = name.toLowerCase(Locale.ENGLISH);
		switch (lowcaseDirectiveName) {
			case "base-uri": {
				// https://w3c.github.io/webappsec-csp/#directive-base-uri
				SourceExpressionDirective thisDirective = new SourceExpressionDirective(values, directiveErrorConsumer);
				if (this.baseUri == null) {
					this.baseUri = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "block-all-mixed-content": {
				// https://www.w3.org/TR/mixed-content/#strict-opt-in
				if (!this.blockAllMixedContent) {
					if (!values.isEmpty()) {
						directiveErrorConsumer.add(Severity.Error, "The block-all-mixed-content directive does not support values", 0);
					}
					this.blockAllMixedContent = true;
				} else {
					wasDupe = true;
				}
				newDirective = new Directive(values);
				break;
			}
			case "form-action": {
				// https://w3c.github.io/webappsec-csp/#directive-form-action
				SourceExpressionDirective thisDirective = new SourceExpressionDirective(values, directiveErrorConsumer);
				if (this.formAction == null) {
					this.formAction = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "frame-ancestors": {
				// https://w3c.github.io/webappsec-csp/#directive-frame-ancestors
				// TODO contemplate warning for paths, which are always ignored: frame-ancestors only matches against origins: https://w3c.github.io/webappsec-csp/#frame-ancestors-navigation-response
				FrameAncestorsDirective thisDirective = new FrameAncestorsDirective(values, directiveErrorConsumer);
				if (this.frameAncestors == null) {
					this.frameAncestors = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "navigate-to": {
				// https://w3c.github.io/webappsec-csp/#directive-navigate-to
				// For some ungodly reason "navigate-to" is a list of source expressions while "frame-ancestors" is not
				// There is no logic here
				SourceExpressionDirective thisDirective = new SourceExpressionDirective(values, directiveErrorConsumer);
				if (this.navigateTo == null) {
					this.navigateTo = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "plugin-types": {
				// https://w3c.github.io/webappsec-csp/#directive-plugin-types
				PluginTypesDirective thisDirective = new PluginTypesDirective(values, directiveErrorConsumer);
				if (this.pluginTypes == null) {
					this.pluginTypes = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "report-to": {
				// https://w3c.github.io/webappsec-csp/#directive-report-to
				if (this.reportTo == null) {
					if (values.isEmpty()) {
						directiveErrorConsumer.add(Severity.Error, "The report-to directive requires a value", -1);
					} else if (values.size() == 1) {
						String token = values.get(0);
						Optional<RFC7230Token> matched = RFC7230Token.parseRFC7230Token(token);
						if (matched.isPresent()) {
							this.reportTo = matched.get();
						} else {
							directiveErrorConsumer.add(Severity.Error, "Expecting RFC 7230 token but found \"" + token + "\"", 0);
						}
					} else {
						directiveErrorConsumer.add(Severity.Error, "The report-to directive requires exactly one value (found " + values.size() + ")", 1);
					}
				} else {
					wasDupe = true;
				}
				newDirective = new Directive(values);
				break;
			}
			case "report-uri": {
				// https://w3c.github.io/webappsec-csp/#directive-report-uri
				directiveErrorConsumer.add(Severity.Warning,"The report-uri directive has been deprecated in favor of the new report-to directive", -1);

				ReportUriDirective thisDirective = new ReportUriDirective(values, directiveErrorConsumer);
				if (this.reportUri == null) {
					this.reportUri = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "sandbox": {
				// https://w3c.github.io/webappsec-csp/#directive-sandbox
				SandboxDirective thisDirective = new SandboxDirective(values, directiveErrorConsumer);
				if (this.sandbox == null) {
					this.sandbox = thisDirective;
				} else {
					wasDupe = true;
				}
				newDirective = thisDirective;
				break;
			}
			case "upgrade-insecure-requests": {
				// https://www.w3.org/TR/upgrade-insecure-requests/#delivery
				if (!this.upgradeInsecureRequests) {
					if (!values.isEmpty()) {
						directiveErrorConsumer.add(Severity.Error, "The upgrade-insecure-requests directive does not support values", 0);
					}
					this.upgradeInsecureRequests = true;
				} else {
					wasDupe = true;
				}
				newDirective = new Directive(values);
				break;
			}
			default: {
				FetchDirectiveKind fetchDirectiveKind = FetchDirectiveKind.fromString(lowcaseDirectiveName);
				if (fetchDirectiveKind != null) {
					SourceExpressionDirective thisDirective = new SourceExpressionDirective(values, directiveErrorConsumer);
					if (this.fetchDirectives.containsKey(fetchDirectiveKind)) {
						wasDupe = true;
					} else {
						this.fetchDirectives.put(fetchDirectiveKind, thisDirective);
					}
					newDirective = thisDirective;
					break;
				}
				directiveErrorConsumer.add(Severity.Warning, "Unrecognized directive " + lowcaseDirectiveName, -1);
				newDirective = new Directive(values);
				break;
			}
		}

		this.directives.add(new NamedDirective(name, newDirective));
		if (wasDupe) {
			directiveErrorConsumer.add(Severity.Warning, "Duplicate directive " + lowcaseDirectiveName, -1);
		}
		return newDirective;
	}

	// Note that this removes all directives matching this name.
	// Returns true if at least one directive was removed.
	public boolean remove(String name) {
		boolean removed = false;
		String lowcaseName = name.toLowerCase(Locale.ENGLISH);
		ArrayList<NamedDirective> copy = new ArrayList<>(this.directives.size());
		for (NamedDirective existing : this.directives) {
			if (!existing.lowcaseName.equals(lowcaseName)) {
				copy.add(existing);
			} else {
				removed = true;
			}
		}
		if (!removed) {
			return false;
		}
		this.directives = copy;
		switch (lowcaseName) {
			case "base-uri": {
				this.baseUri = null;
				break;
			}
			case "block-all-mixed-content": {
				this.blockAllMixedContent = false;
				break;
			}
			case "form-action": {
				this.formAction = null;
				break;
			}
			case "frame-ancestors": {
				this.frameAncestors = null;
				break;
			}
			case "navigate-to": {
				this.navigateTo = null;
				break;
			}
			case "plugin-types": {
				this.pluginTypes = null;
				break;
			}
			case "report-to": {
				this.reportTo = null;
				break;
			}
			case "report-uri": {
				this.reportUri = null;
				break;
			}
			case "sandbox": {
				this.sandbox = null;
				break;
			}
			case "upgrade-insecure-requests": {
				this.upgradeInsecureRequests = false;
				break;
			}
			default: {
				FetchDirectiveKind fetchDirectiveKind = FetchDirectiveKind.fromString(lowcaseName);
				if (fetchDirectiveKind != null) {
					this.fetchDirectives.remove(fetchDirectiveKind);
				}
				break;
			}
		}
		return true;
	}


	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();
		boolean first = true;
		for (NamedDirective directive : this.directives) {
			if (!first) {
				out.append("; "); // The whitespace is not strictly necessary but is probably valuable
			}
			first = false;
			out.append(directive.name);
			for (String value : directive.directive.getValues()) {
				out.append(' ');
				out.append(value);
			}
		}
		return out.toString();
	}

	// Accessors


	public Optional<SourceExpressionDirective> baseUri() {
		return Optional.ofNullable(this.baseUri);
	}

	public boolean blockAllMixedContent() {
		return this.blockAllMixedContent;
	}

	public void setBlockAllMixedContent(boolean value) {
		if (this.blockAllMixedContent) {
			if (value) {
				return;
			}
			this.remove("block-all-mixed-content");
		} else {
			if (!value) {
				return;
			}
			this.blockAllMixedContent = true;
			this.directives.add(new NamedDirective("block-all-mixed-content", new Directive(Collections.emptyList())));
		}
	}

	public Optional<SourceExpressionDirective> formAction() {
		return Optional.ofNullable(this.formAction);
	}

	public Optional<FrameAncestorsDirective> frameAncestors() {
		return Optional.ofNullable(this.frameAncestors);
	}

	public Optional<SourceExpressionDirective> navigateTo() {
		return Optional.ofNullable(this.navigateTo);
	}

	public Optional<PluginTypesDirective> pluginTypes() {
		return Optional.ofNullable(this.pluginTypes);
	}

	public Optional<RFC7230Token> reportTo() {
		return Optional.ofNullable(this.reportTo);
	}

	public void setReportTo(RFC7230Token token) {
		if (token == null) {
			this.remove("report-to");
			return;
		}

		// We can't switch on `this.reportTo` being non-null because it can also be null if the directive exists but was malformed
		boolean found = false;
		for (NamedDirective directive : this.directives) {
			if (directive.lowcaseName.equals("report-to")) {
				directive.directive.values = new ArrayList<>();
				// using addValue gives us its sanity checks
				directive.directive.addValue(token.value);
				found = true;
				break;
			}
		}
		if (!found) {
			this.directives.add(new NamedDirective("report-to", new Directive(Collections.singletonList(token.value))));
		}
		this.reportTo = token;
	}

	public Optional<ReportUriDirective> reportUri() {
		return Optional.ofNullable(this.reportUri);
	}

	public Optional<SandboxDirective> sandbox() {
		return Optional.ofNullable(this.sandbox);
	}

	public boolean upgradeInsecureRequests() {
		return this.upgradeInsecureRequests;
	}

	public void setUpgradeInsecureRequests(boolean value) {
		if (this.upgradeInsecureRequests) {
			if (value) {
				return;
			}
			this.remove("upgrade-insecure-requests");
		} else {
			if (!value) {
				return;
			}
			this.upgradeInsecureRequests = true;
			this.directives.add(new NamedDirective("upgrade-insecure-requests", new Directive(Collections.emptyList())));
		}
	}

	public Optional<SourceExpressionDirective> getFetchDirective(FetchDirectiveKind kind) {
		return Optional.ofNullable(this.fetchDirectives.get(kind));
	}


	// High-level querying


	/*
	For each of these arguments, if the value provided is Optional.empty(), this method will return `true` only if there is no value for the Optional.of() case of that parameter which would cause it to return `false`.
	Take care with `integrity`; your script can be allowed by CSP but blocked by SRI if its integrity is wrong.
	See https://www.w3.org/TR/SRI/
	Also note that the notion of "the URL" is a little fuzzy because there can be redirects.
	https://w3c.github.io/webappsec-csp/#script-pre-request
	https://w3c.github.io/webappsec-csp/#script-post-request
	 */
	public boolean allowsExternalScript(Optional<String> nonce, Optional<String> integrity, Optional<URLWithScheme> scriptUrl, Optional<Boolean> parserInserted, Optional<URLWithScheme> origin) {
		if (this.sandbox != null && !this.sandbox.allowScripts()) {
			return false;
		}
		// Effective directive is "script-src-elem" per https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request
		SourceExpressionDirective directive = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ScriptSrcElem).orElse(null);
		if (directive == null) {
			return true;
		}
		if (nonce.isPresent()) {
			String actualNonce = nonce.get();
			if (actualNonce.length() > 0 && directive.getNonces().stream().anyMatch(n -> n.base64ValuePart.equals(actualNonce))) {
				return true;
			}
		}
		if (integrity.isPresent() && !directive.getHashes().isEmpty()) {
			String integritySources = integrity.get();
			boolean bypassDueToIntegrityMatch = true;
			boolean atLeastOneValidIntegrity = false;
			// https://www.w3.org/TR/SRI/#parse-metadata
			for (String source : Utils.splitOnAsciiWhitespace(integritySources)) {
				Optional<Hash> parsedIntegritySource = Hash.parseHash("'" + source + "'");
				if (!parsedIntegritySource.isPresent()) {
					continue;
				}
				if (!directive.getHashes().contains(parsedIntegritySource.get())) {
					bypassDueToIntegrityMatch = false;
					break;
				}
				atLeastOneValidIntegrity = true;
			}
			if (atLeastOneValidIntegrity && bypassDueToIntegrityMatch) {
				return true;
			}
		}
		if (directive.strictDynamic()) {
			return !parserInserted.orElse(true); // if not the parameter is not supplied, we have to assume the worst case
		}
		if (scriptUrl.isPresent()) {
			return doesUrlMatchSourceListInOrigin(scriptUrl.get(), directive, origin);
		}
		return false;
	}

	// https://w3c.github.io/webappsec-csp/#script-src-elem-inline
	public boolean allowsInlineScript(Optional<String> nonce, Optional<String> source, Optional<Boolean> parserInserted) {
		if (this.sandbox != null && !this.sandbox.allowScripts()) {
			return false;
		}
		return doesElementMatchSourceListForTypeAndSource(InlineType.Script, nonce, source, parserInserted);
	}

	// https://w3c.github.io/webappsec-csp/#script-src-attr-inline
	public boolean allowsScriptAsAttribute(Optional<String> source) {
		if (this.sandbox != null && !this.sandbox.allowScripts()) {
			return false;
		}
		return doesElementMatchSourceListForTypeAndSource(InlineType.ScriptAttribute, Optional.empty(), source, Optional.empty());
	}

	// https://w3c.github.io/webappsec-csp/#can-compile-strings
	public boolean allowsEval() {
		// This is done in prose, not in a table
		FetchDirectiveKind governingDirective = this.fetchDirectives.containsKey(FetchDirectiveKind.ScriptSrc) ? FetchDirectiveKind.ScriptSrc : FetchDirectiveKind.DefaultSrc;
		SourceExpressionDirective sourceList = this.fetchDirectives.get(governingDirective);
		return sourceList == null || sourceList.unsafeEval();
	}

	// https://w3c.github.io/webappsec-csp/#navigate-to-pre-navigate
	// https://w3c.github.io/webappsec-csp/#navigate-to-navigation-response
	// Strictly speaking this requires the _response_'s CSP as well, because of frame-ancestors.
	// But we are maybe not going to worry about that.
	// Note: it is nonsensical to provide redirectedTo if redirected is Optional.of(false)
	// Note: this also does not handle `javascript:` navigation; there's an explicit API for that
	public boolean allowsNavigation(Optional<URLWithScheme> to, Optional<Boolean> redirected, Optional<URLWithScheme> redirectedTo, Optional<URLWithScheme> origin) {
		if (this.navigateTo == null) {
			return true;
		}
		if (this.navigateTo.unsafeAllowRedirects()) {
			// if unsafe-allow-redirects is present, check `to` in non-redirect or maybe-non-redirect cases
			if (!redirected.orElse(false)) {
				if (!to.isPresent()) {
					return false;
				}
				if (!doesUrlMatchSourceListInOrigin(to.get(), navigateTo, origin)) {
					return false;
				}
			}
			// if unsafe-allow-redirects is present, check `redirectedTo` in redirect or maybe-redirect cases
			if (redirected.orElse(true)) {
				if (!redirectedTo.isPresent()) {
					return false;
				}
				if (!doesUrlMatchSourceListInOrigin(redirectedTo.get(), navigateTo, origin)) {
					return false;
				}
			}
		} else {
			// if unsafe-allow-redirects is absent, always and only check `to`
			if (!to.isPresent()) {
				return false;
			}
			if (!doesUrlMatchSourceListInOrigin(to.get(), navigateTo, origin)) {
				return false;
			}
		}
		return true;
	}

	// https://w3c.github.io/webappsec-csp/#navigate-to-pre-navigate
	// https://w3c.github.io/webappsec-csp/#navigate-to-navigation-response
	// Note: it is nonsensical to provide redirectedTo if redirected is Optional.of(false)
	public boolean allowsFormAction(Optional<URLWithScheme> to, Optional<Boolean> redirected, Optional<URLWithScheme> redirectedTo, Optional<URLWithScheme> origin) {
		if (this.sandbox != null && !this.sandbox.allowForms()) {
			return false;
		}
		if (this.formAction != null) {
			if (!to.isPresent()) {
				return false;
			}
			if (!doesUrlMatchSourceListInOrigin(to.get(), this.formAction, origin)) {
				return false;
			}
			return true;
		} else {
			// this isn't implemented like other fallbacks because it isn't one: form-action does not respect unsafe-allow-redirects
			return this.allowsNavigation(to, redirected, redirectedTo, origin);
		}
	}

	// NB: the hashes (for unsafe-hashes) are supposed to include the javascript: part, per spec
	public boolean allowsJavascriptUrlNavigation(Optional<String> source, Optional<URLWithScheme> origin) {
		return this.allowsNavigation(Optional.of(new GUID("javascript", source.orElse(""))), Optional.of(false), Optional.empty(), origin)
				&& this.doesElementMatchSourceListForTypeAndSource(InlineType.Navigation, Optional.empty(), source.map(s -> "javascript:" + s), Optional.of(false));
	}

	public boolean allowsExternalStyle(Optional<String> nonce, Optional<URLWithScheme> styleUrl, Optional<URLWithScheme> origin) {
		// Effective directive is "script-src-elem" per https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request
		SourceExpressionDirective directive = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.StyleSrcElem).orElse(null);
		if (directive == null) {
			return true;
		}
		if (nonce.isPresent()) {
			String actualNonce = nonce.get();
			if (actualNonce.length() > 0 && directive.getNonces().stream().anyMatch(n -> n.base64ValuePart.equals(actualNonce))) {
				return true;
			}
		}
		// integrity is not used: https://github.com/w3c/webappsec-csp/issues/430
		if (styleUrl.isPresent()) {
			return doesUrlMatchSourceListInOrigin(styleUrl.get(), directive, origin);
		}
		return false;
	}

	public boolean allowsInlineStyle(Optional<String> nonce, Optional<String> source) {
		return doesElementMatchSourceListForTypeAndSource(InlineType.Style, nonce, source, Optional.empty());
	}

	public boolean allowsStyleAsAttribute(Optional<String> source) {
		return doesElementMatchSourceListForTypeAndSource(InlineType.StyleAttribute, Optional.empty(), source, Optional.empty());
	}

	public boolean allowsFrame(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.FrameSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsFrameAncestor(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		if (this.frameAncestors == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), frameAncestors, origin);
	}


	// This assumes that a `ws:` or `wss:` URL is being used with `new WebSocket` specifically
	public boolean allowsConnection(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ConnectSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		// See https://fetch.spec.whatwg.org/#concept-websocket-establish
		// Also browsers don't implement this; see https://github.com/w3c/webappsec-csp/issues/429
		URLWithScheme actualSource = source.get();
		String scheme = actualSource.scheme;
		URLWithScheme usedSource = actualSource;
		if (actualSource instanceof URI) {
			if (scheme.equals("ws")) {
				usedSource = new URI("http", actualSource.host, actualSource.port, actualSource.path);
			} else if (scheme.equals("wss")) {
				usedSource = new URI("https", actualSource.host, actualSource.port, actualSource.path);
			}
		}

		return doesUrlMatchSourceListInOrigin(usedSource, sourceList, origin);
	}

	public boolean allowsFont(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.FontSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsImage(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ImgSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsApplicationManifest(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ManifestSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsMedia(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.MediaSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsObject(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ObjectSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	// Not actually spec'd properly; see https://github.com/whatwg/fetch/issues/1008
	public boolean allowsPrefetch(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.PrefetchSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsWorker(Optional<URLWithScheme> source, Optional<URLWithScheme> origin) {
		SourceExpressionDirective sourceList = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.WorkerSrc).orElse(null);
		if (sourceList == null) {
			return true;
		}
		if (!source.isPresent()) {
			return false;
		}
		return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
	}

	public boolean allowsPlugin(Optional<MediaType> mediaType) {
		if (this.pluginTypes == null) {
			return true;
		}
		if (!mediaType.isPresent()) {
			return false;
		}
		return this.pluginTypes.getMediaTypes().contains(mediaType.get());
	}


	// https://w3c.github.io/webappsec-csp/#should-directive-execute
	public Optional<SourceExpressionDirective> getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind kind) {
		for (FetchDirectiveKind candidate : FetchDirectiveKind.getFetchDirectiveFallbackList(kind)) {
			SourceExpressionDirective list = this.fetchDirectives.get(candidate);
			if (list != null) {
				return Optional.of(list);
			}
		}
		return Optional.empty();
	}

	// https://w3c.github.io/webappsec-csp/#directive-inline-check
	// https://w3c.github.io/webappsec-csp/#should-block-inline specifies the first four values
	// https://w3c.github.io/webappsec-csp/#should-block-navigation-request specifies "navigation", used for `javascript:` urls
	// https://w3c.github.io/webappsec-csp/#effective-directive-for-inline-check
	private enum InlineType {
		Script(FetchDirectiveKind.ScriptSrcElem),
		ScriptAttribute(FetchDirectiveKind.ScriptSrcAttr),
		Style(FetchDirectiveKind.StyleSrcElem),
		StyleAttribute(FetchDirectiveKind.StyleSrcAttr),
		Navigation(FetchDirectiveKind.ScriptSrcElem);

		final FetchDirectiveKind effectiveDirective;

		InlineType(FetchDirectiveKind effectiveDirective) {
			this.effectiveDirective = effectiveDirective;
		}
	}

	// Note: this assumes the element is nonceable. See https://w3c.github.io/webappsec-csp/#is-element-nonceable
	// https://w3c.github.io/webappsec-csp/#match-element-to-source-list
	private boolean doesElementMatchSourceListForTypeAndSource(InlineType type, Optional<String> nonce, Optional<String> source, Optional<Boolean> parserInserted) {
		SourceExpressionDirective directive = getGoverningDirectiveForEffectiveDirective(type.effectiveDirective).orElse(null);
		if (directive == null) {
			return true;
		}
		// https://w3c.github.io/webappsec-csp/#allow-all-inline
		boolean allowAllInline = directive.getNonces().isEmpty() && directive.getHashes().isEmpty()
				&& !((type == InlineType.Script || type == InlineType.ScriptAttribute || type == InlineType.Navigation) && directive.strictDynamic())
				&& directive.unsafeInline();
		if (allowAllInline) {
			return true;
		}
		if (nonce.isPresent()) {
			String actualNonce = nonce.get();
			if (actualNonce.length() > 0 && directive.getNonces().stream().anyMatch(n -> n.base64ValuePart.equals(actualNonce))) {
				return true;
			}
		}
		if (source.isPresent() && !directive.getHashes().isEmpty() && (type == InlineType.Script || type == InlineType.Style || directive.unsafeHashes())) {
			byte[] actualSource = source.get().getBytes(StandardCharsets.UTF_8);
			Base64.Encoder base64encoder = Base64.getEncoder();
			String actualSha256 = null;
			String actualSha384 = null;
			String actualSha512 = null;
			try {
				for (Hash hash : directive.getHashes()) {
					switch (hash.algorithm) {
						case SHA256:
							if (actualSha256 == null) {
								actualSha256 = base64encoder.encodeToString(MessageDigest.getInstance("SHA-256").digest(actualSource));
							}
							if (actualSha256.equals(normalizeBase64Url(hash.base64ValuePart))) {
								return true;
							}
							break;
						case SHA384:
							if (actualSha384 == null) {
								actualSha384 = base64encoder.encodeToString(MessageDigest.getInstance("SHA-384").digest(actualSource));
							}
							if (actualSha384.equals(normalizeBase64Url(hash.base64ValuePart))) {
								return true;
							}
							break;
						case SHA512:
							if (actualSha512 == null) {
								actualSha512 = base64encoder.encodeToString(MessageDigest.getInstance("SHA-512").digest(actualSource));
							}
							if (actualSha512.equals(normalizeBase64Url(hash.base64ValuePart))) {
								return true;
							}
							break;
						default:
							throw new IllegalArgumentException("Unknown hash algorithm " + hash.algorithm);
					}
				}
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		}
		// This is not per spec, but matches implementations and the spec author's intent: https://github.com/w3c/webappsec-csp/issues/426
		if (type == InlineType.Script && directive.strictDynamic() && !parserInserted.orElse(true)) {
			return true;
		}
		return false;
	}

	private static String normalizeBase64Url(String input) {
		return input.replace('-', '+').replace('_', '/');
	}

	// https://w3c.github.io/webappsec-csp/#match-url-to-source-list
	public static boolean doesUrlMatchSourceListInOrigin(URLWithScheme url, HostSourceDirective list, Optional<URLWithScheme> origin) {
		String urlScheme = url.scheme;
		if (list.star()) {
			// https://fetch.spec.whatwg.org/#network-scheme
			// Note that "ws" and "wss" are _not_ network schemes
			if (Objects.equals(urlScheme, "ftp") || Objects.equals(urlScheme, "http") || Objects.equals(urlScheme, "https")) {
				return true;
			}
			if (origin.isPresent() && Objects.equals(urlScheme, origin.get().scheme)) {
				return true;
			}
		}
		for (Scheme scheme : list.getSchemes()) {
			if (schemePartMatches(scheme.value, urlScheme)) {
				return true;
			}
		}
		for (Host expression : list.getHosts()) {
			String scheme = expression.scheme;
			if (scheme != null) {
				if (!schemePartMatches(scheme, urlScheme)) {
					continue;
				}
			} else {
				if (!origin.isPresent() || !schemePartMatches(origin.get().scheme, urlScheme)) {
					continue;
				}
			}
			if (url.host == null) {
				continue;
			}
			if (!hostPartMatches(expression.host, url.host)) {
				continue;
			}
			// url.port is non-null whenever url.host is
			if (!portPartMatches(expression.port, url.port, urlScheme)) {
				continue;
			}
			if (!pathPartMatches(expression.path, url.path)) {
				continue;
			}
			return true;
		}
		if (list.self()) {
			if (origin.isPresent()) {
				URLWithScheme actualOrigin = origin.get();
				String originScheme = actualOrigin.scheme;
				if (
						Objects.equals(actualOrigin.host, url.host)
						&& (Objects.equals(actualOrigin.port, url.port) || Objects.equals(actualOrigin.port, URI.defaultPortForProtocol(originScheme)) && Objects.equals(url.port, URI.defaultPortForProtocol(urlScheme)))
						&& (urlScheme.equals("https") || urlScheme.equals("wss") || originScheme.equals("http") && (urlScheme.equals("http") || urlScheme.equals("ws")))
				) {
					return true;
				}
			}
		}
		return false;
	}

	// https://w3c.github.io/webappsec-csp/#scheme-part-match
	private static boolean schemePartMatches(String A, String B) {
		// Assumes inputs are already lowcased
		return A.equals(B)
				|| A.equals("http") && B.equals("https")
				|| A.equals("ws") && (B.equals("wss") || B.equals("http") || B.equals("https"))
				|| A.equals("wss") && B.equals("https");
	}

	// https://w3c.github.io/webappsec-csp/#host-part-match
	private static boolean hostPartMatches(String A, String B) {
		if (A.startsWith("*")) {
			String remaining = A.substring(1);
			return B.toLowerCase(Locale.ENGLISH).endsWith(remaining.toLowerCase(Locale.ENGLISH));
		}

		if (!A.equalsIgnoreCase(B)) {
			return false;
		}

		Matcher IPv4Matcher = Constants.IPv4address.matcher(A);
		Matcher IPv6Matcher = Constants.IPv6addressWithOptionalBracket.matcher(A);
		Matcher IPv6LoopbackMatcher = Constants.IPV6loopback.matcher(A);
		if ((IPv4Matcher.find() && !A.equals("127.0.0.1")) || IPv6Matcher.find() || IPv6LoopbackMatcher.find()) {
			return false;
		}
		return true;
	}

	// https://w3c.github.io/webappsec-csp/#port-part-matches
	private static boolean portPartMatches(int A, int portB, String schemeB) {
		if (A == Constants.EMPTY_PORT) {
			return portB == URI.defaultPortForProtocol(schemeB);
		}
		if (A == Constants.WILDCARD_PORT) {
			return true;
		}
		if (A == portB) {
			return true;
		}
		if (portB == Constants.EMPTY_PORT) {
			return A == URI.defaultPortForProtocol(schemeB);
		}
		return false;
	}

	// https://w3c.github.io/webappsec-csp/#path-part-match
	private static boolean pathPartMatches(String pathA, String pathB) {
		if (pathA == null) pathA = "";
		if (pathB == null) pathB = "";

		if (pathA.isEmpty()) {
			return true;
		}

		if (pathA.equals("/") && pathB.isEmpty()) {
			return true;
		}

		boolean exactMatch = !pathA.endsWith("/");

		List<String> pathListA = Utils.strictlySplit(pathA, '/');
		List<String> pathListB = Utils.strictlySplit(pathB, '/');

		if (pathListA.size() > pathListB.size()) {
			return false;
		}

		if (exactMatch && pathListA.size() != pathListB.size()) {
			return false;
		}

		if (!exactMatch) {
			pathListA.remove(pathListA.size() - 1);
		}

		Iterator<String> it1 = pathListA.iterator();
		Iterator<String> it2 = pathListB.iterator();

		while (it1.hasNext()) {
			String a = Utils.decodeString(it1.next());
			String b = Utils.decodeString(it2.next());
			if (!a.equals(b)) {
				return false;
			}
		}
		return true;
	}


	// Utilities and helper classes

	static void enforceAscii(String s) {
		if (!StandardCharsets.US_ASCII.newEncoder().canEncode(s)) {
			throw new IllegalArgumentException("string is not ascii: \"" + s + "\"");
		}
	}

	private static String stripLeadingWhitespace(String string) {
		return string.replaceFirst("^[" + Constants.WHITESPACE_CHARS + "]+", "");
	}

	private static String stripTrailingWhitespace(String string) {
		return string.replaceAll("[" + Constants.WHITESPACE_CHARS + "]+$", "");
	}

	private static boolean containsLeadingWhitespace(String string) {
		Matcher matcher = Pattern.compile("[" + Constants.WHITESPACE_CHARS + "]+").matcher(string);
		return matcher.find() && matcher.start() == 0;
	}

	@Nonnull
	private static String collect(String input, String regex) {
		Matcher matcher = Pattern.compile(regex).matcher(input);
		if (!matcher.find() || matcher.start() != 0) {
			return "";
		}
		return input.substring(0, matcher.end());
	}


	private static class NamedDirective {
		final String name;
		final Directive directive;
		final String lowcaseName;

		private NamedDirective(String name, Directive directive) {
			this.name = name;
			this.directive = directive;
			this.lowcaseName = this.name.toLowerCase(Locale.ENGLISH);
		}
	}

	// Info: strictly informative
	// Warning: it matches the grammar, but is meaningless, duplicated, or otherwise problematic
	// Error: it does not match the grammar
	public enum Severity { Info, Warning, Error }

	@FunctionalInterface
	public interface PolicyErrorConsumer {
		void add(Severity severity, String message, int directiveIndex, int valueIndex); // valueIndex = -1 for errors not pertaining to a value

		PolicyErrorConsumer ignored = (severity, message, directiveIndex, valueIndex) -> {};
	}

	@FunctionalInterface
	public interface PolicyListErrorConsumer {
		void add(Severity severity, String message, int policyIndex, int directiveIndex, int valueIndex); // valueIndex = -1 for errors not pertaining to a value

		PolicyListErrorConsumer ignored = (severity, message, policyIndex, directiveIndex, valueIndex) -> {};
	}
}
