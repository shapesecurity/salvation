package com.shapesecurity.salvation2;

import com.shapesecurity.salvation2.URLs.URLWithScheme;

import java.util.Optional;

public class PolicyInOrigin {
	public final Policy policy;
	public final URLWithScheme origin;

	public PolicyInOrigin(Policy policy, URLWithScheme origin) {
		this.policy = policy;
		this.origin = origin;
	}



	// Low-level querying

	public boolean allowsScriptFromSource(URLWithScheme url) {
		return this.policy.allowsExternalScript(Optional.empty(), Optional.empty(), Optional.of(url), Optional.empty(), Optional.of(this.origin));
	}

	public boolean allowsStyleFromSource(URLWithScheme url) {
		return this.policy.allowsExternalStyle(Optional.empty(), Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsImageFromSource(URLWithScheme url) {
		return this.policy.allowsImage(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsFrameFromSource(URLWithScheme url) {
		return this.policy.allowsFrame(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsWorkerFromSource(URLWithScheme url) {
		return this.policy.allowsWorker(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsFontFromSource(URLWithScheme url) {
		return this.policy.allowsFont(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsObjectFromSource(URLWithScheme url) {
		return this.policy.allowsObject(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsMediaFromSource(URLWithScheme url) {
		return this.policy.allowsMedia(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsManifestFromSource(URLWithScheme url) {
		return this.policy.allowsApplicationManifest(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsPrefetchFromSource(URLWithScheme url) {
		return this.policy.allowsPrefetch(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsUnsafeInlineScript() {
		return this.policy.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty());
	}

	public boolean allowsUnsafeInlineStyle() {
		return this.policy.allowsInlineStyle(Optional.empty(), Optional.empty());
	}

	public boolean allowsConnection(URLWithScheme url) {
		return this.policy.allowsConnection(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsNavigation(URLWithScheme url) {
		return this.policy.allowsNavigation(Optional.of(url), Optional.empty(), Optional.empty(), Optional.of(this.origin));
	}

	public boolean allowsFrameAncestor(URLWithScheme url) {
		return this.policy.allowsFrameAncestor(Optional.of(url), Optional.of(this.origin));
	}

	public boolean allowsFormAction(URLWithScheme url) {
		return this.policy.allowsFormAction(Optional.of(url), Optional.empty(), Optional.empty(), Optional.of(this.origin));
	}


}
