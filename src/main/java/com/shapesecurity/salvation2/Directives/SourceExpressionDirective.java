package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Policy;
import com.shapesecurity.salvation2.Values.Hash;
import com.shapesecurity.salvation2.Values.Nonce;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public class SourceExpressionDirective extends HostSourceDirective {
	private static final String REPORT_SAMPLE = "'report-sample'";
	private static final String UNSAFE_INLINE = "'unsafe-inline'";
	private static final String STRICT_DYNAMIC = "'strict-dynamic'";
	private static final String UNSAFE_ALLOW_REDIRECTS = "'unsafe-allow-redirects'";
	private static final String UNSAFE_EVAL = "'unsafe-eval'";
	private static final String UNSAFE_HASHES = "'unsafe-hashes'";
	private boolean unsafeInline = false;
	private boolean unsafeEval = false;
	private boolean strictDynamic = false;
	private boolean unsafeHashes = false;
	private boolean reportSample = false;
	private boolean unsafeAllowRedirects = false;

	// In practice, these are probably small enough for Lists to be faster than LinkedHashSets
	private List<Nonce> nonces = new ArrayList<>();
	private List<Hash> hashes = new ArrayList<>();


	public SourceExpressionDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);

		int index = 0;
		for (String token : values) {
			// The CSP grammar uses ABNF grammars, whose strings are case-insensitive: https://tools.ietf.org/html/rfc5234
			String lowcaseToken = token.toLowerCase(Locale.ENGLISH); // This needs to be ASCII-lowercase, so that `'strIct-dynamic''` still parses in Turkey
			switch (lowcaseToken) {
				case UNSAFE_INLINE:
					if (!this.unsafeInline) {
						this.unsafeInline = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-inline'", index);
					}
					break;
				case UNSAFE_EVAL:
					if (!this.unsafeEval) {
						this.unsafeEval = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-eval'", index);
					}
					break;
				case STRICT_DYNAMIC:
					if (!this.strictDynamic) {
						this.strictDynamic = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate source-expression 'strict-dynamic'", index);
					}
					break;
				case UNSAFE_HASHES:
					if (!this.unsafeHashes) {
						this.unsafeHashes = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-hashes'", index);
					}
					break;
				case REPORT_SAMPLE:
					if (!this.reportSample) {
						this.reportSample = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate source-expression 'report-sample'", index);
					}
					break;
				case UNSAFE_ALLOW_REDIRECTS:
					if (!this.unsafeAllowRedirects) {
						this.unsafeAllowRedirects = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-allow-redirects'", index);
					}
					break;
				case "'unsafe-redirect'":
					errors.add(Policy.Severity.Error, "'unsafe-redirect' has been removed from CSP as of version 2.0", index);
					break;
				case "'unsafe-hashed-attributes'":
					errors.add(Policy.Severity.Error, "'unsafe-hashed-attributes' was renamed to 'unsafe-hashes' in June 2018", index);
					break;
				default:
					if (lowcaseToken.startsWith("'nonce-")) {
						// the above check is not strictly necessary, but allows us to give a better message for nonce-likes which don't match the base64 grammar
						Optional<Nonce> nonce = Nonce.parseNonce(token);
						if (nonce.isPresent()) {
							this._addNonce(nonce.get(), index, errors);
						} else {
							errors.add(Policy.Severity.Error, "Unrecognised nonce " + token, index);
						}
						break;
					} else if (lowcaseToken.startsWith("'sha")) {
						// the above check is not strictly necessary, but allows us to give a better message for hash-likes which don't match the base64 grammar
						Optional<Hash> hash = Hash.parseHash(token);
						if (hash.isPresent()) {
							this._addHash(hash.get(), index, errors);
						} else {
							errors.add(Policy.Severity.Error, "'sha...' source-expression uses an unrecognized algorithm or does not match the base64-value grammar (or is missing its trailing \"'\")", index);
						}
						break;
					} else {
						this._addHostOrSchemeDuringConstruction(token, lowcaseToken, "source-expression", index, errors);
					}
			}
			++index;
		}

		if (this.none != null && values.size() > 1) {
			errors.add(Policy.Severity.Error, "'none' must not be combined with any other source-expression", 1);
		}

		if (values.isEmpty()) {
			errors.add(Policy.Severity.Error, "Source-expression lists cannot be empty (use 'none' instead)", -1);
		}
	}

	private boolean _addNonce(Nonce nonce, int index, DirectiveErrorConsumer errors) {
		if (this.nonces.contains(nonce)) {
			errors.add(Policy.Severity.Warning, "Duplicate nonce " + nonce.toString(), index);
			return false;
		} else {
			this.nonces.add(nonce);
			return true;
		}
	}

	private boolean _addHash(Hash hash, int index, DirectiveErrorConsumer errors) {
		if (this.hashes.contains(hash)) {
			errors.add(Policy.Severity.Warning, "Duplicate hash " + hash.toString(), index);
			return false;
		} else {
			if (hash.base64ValuePart.length() != hash.algorithm.length) {
				errors.add(Policy.Severity.Warning, "Wrong length for " + hash.algorithm.toString() + ": expected " + hash.algorithm.length + ", got " + hash.base64ValuePart.length(), index);
			}

			if (hash.base64ValuePart.contains("_") || hash.base64ValuePart.contains("-")) {
				errors.add(Policy.Severity.Warning, "'_' and '-' in hashes can never match actual elements", index);
			}

			this.hashes.add(hash);
			return true;
		}
	}



	// Accessors

	// TODO it would be nice to warn for adding things which are irrelevant
	// Though it would be better to just not provide those methods at all
	// But that kind of conflicts with the "only error on things which don't match the grammar" goal
	// See also https://github.com/w3c/webappsec-csp/issues/431

	public boolean unsafeInline() {
		return this.unsafeInline;
	}

	public void setUnsafeInline(boolean unsafeInline) {
		if (this.unsafeInline == unsafeInline) {
			return;
		}
		if (unsafeInline) {
			this.addValue(UNSAFE_INLINE);
		} else {
			this.removeValueIgnoreCase(UNSAFE_INLINE);
		}
		this.unsafeInline = unsafeInline;
	}


	public boolean unsafeEval() {
		return this.unsafeEval;
	}

	public void setUnsafeEval(boolean unsafeEval) {
		if (this.unsafeEval == unsafeEval) {
			return;
		}
		if (unsafeEval) {
			this.addValue(UNSAFE_EVAL);
		} else {
			this.removeValueIgnoreCase(UNSAFE_EVAL);
		}
		this.unsafeEval = unsafeEval;
	}


	public boolean strictDynamic() {
		return this.strictDynamic;
	}

	public void setStrictDynamic(boolean strictDynamic) {
		if (this.strictDynamic == strictDynamic) {
			return;
		}
		if (strictDynamic) {
			this.addValue(STRICT_DYNAMIC);
		} else {
			this.removeValueIgnoreCase(STRICT_DYNAMIC);
		}
		this.strictDynamic = strictDynamic;
	}


	public boolean unsafeHashes() {
		return this.unsafeHashes;
	}

	public void setUnsafeHashes(boolean unsafeHashes) {
		if (this.unsafeHashes == unsafeHashes) {
			return;
		}
		if (unsafeHashes) {
			this.addValue(UNSAFE_HASHES);
		} else {
			this.removeValueIgnoreCase(UNSAFE_HASHES);
		}
		this.unsafeHashes = unsafeHashes;
	}


	public boolean reportSample() {
		return this.reportSample;
	}

	public void setReportSample(boolean reportSample) {
		if (this.reportSample == reportSample) {
			return;
		}
		if (reportSample) {
			this.addValue(REPORT_SAMPLE);
		} else {
			this.removeValueIgnoreCase(REPORT_SAMPLE);
		}
		this.reportSample = reportSample;
	}


	public boolean unsafeAllowRedirects() {
		return this.unsafeAllowRedirects;
	}

	public void setUnsafeAllowRedirects(boolean unsafeAllowRedirects) {
		if (this.unsafeAllowRedirects == unsafeAllowRedirects) {
			return;
		}
		if (unsafeAllowRedirects) {
			this.addValue(UNSAFE_ALLOW_REDIRECTS);
		} else {
			this.removeValueIgnoreCase(UNSAFE_ALLOW_REDIRECTS);
		}
		this.unsafeAllowRedirects = unsafeAllowRedirects;
	}


	public List<Nonce> getNonces() {
		return Collections.unmodifiableList(this.nonces);
	}

	public void addNonce(Nonce nonce, ManipulationErrorConsumer errors) {
		if (this._addNonce(nonce, -1, wrapManipulationErrorConsumer(errors))) {
			this.addValue(nonce.toString());
		}
	}

	public boolean removeNonce(Nonce nonce) {
		if (!this.nonces.contains(nonce)) {
			return false;
		}
		this.nonces.remove(nonce);
		// we can't just "removeValue" or "removeValueIgnoreCase" because the `nonce-` part is case-insensitive but the remainder is case-sensitive
		this.removeValuesMatching(nonce, Nonce::parseNonce);
		return true;
	}

	public List<Hash> getHashes() {
		return Collections.unmodifiableList(this.hashes);
	}

	public void addHash(Hash hash, ManipulationErrorConsumer errors) {
		if (this._addHash(hash, -1, wrapManipulationErrorConsumer(errors))) {
			this.addValue(hash.toString());
		}
	}

	public boolean removeHash(Hash hash) {
		if (!this.hashes.contains(hash)) {
			return false;
		}
		this.hashes.remove(hash);
		// we can't just "removeValue" or "removeValueIgnoreCase" because the `sha256-` part is case-insensitive but the remainder is case-sensitive
		this.removeValuesMatching(hash, Hash::parseHash);
		return true;
	}
}
