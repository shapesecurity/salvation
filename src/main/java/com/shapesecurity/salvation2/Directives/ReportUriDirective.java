package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Directive;
import com.shapesecurity.salvation2.Policy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ReportUriDirective extends Directive {
	private List<String> uris = new ArrayList<>();

	public ReportUriDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);
		int index = 0;
		for (String value : values) {
			this._addUri(value, index, errors);
			++index;
		}

		if (this.values.isEmpty()) {
			errors.add(Policy.Severity.Error, "The report-uri value requires at least one value", -1);
		}
	}

	private void _addUri(String uri, int index, DirectiveErrorConsumer errors) {
		// TODO actual parsing per https://tools.ietf.org/html/rfc3986#section-4.1
		// It's awful, though: 'urn:example:animal:ferret:nose' is a valid URI
		if (this.uris.contains(uri)) {
			// NB: we don't prevent you from having duplicates, because that has actual semantic meaning - it will get each report twice (per spec)
			errors.add(Policy.Severity.Info, "Duplicate report-to URI; are you sure you intend to get multiple copies of each report?", index);
		}
		this.uris.add(uri);
	}

	public List<String> getUris() {
		return Collections.unmodifiableList(uris);
	}

	public void addUri(String uri, ManipulationErrorConsumer errors) {
		this._addUri(uri, -1, wrapManipulationErrorConsumer(errors));
		this.addValue(uri);
	}

	// Note that this removes all copies, not just the first
	public boolean removeUri(String uri) {
		if (!this.uris.contains(uri)) {
			return false;
		}
		while (this.uris.contains(uri)) {
			this.uris.remove(uri);
		}

		ArrayList<String> copy = new ArrayList<>(this.values.size());
		for (String existing : this.values) {
			if (!existing.equals(uri)) {
				copy.add(existing);
			}
		}
		this.values = copy;
		return true;
	}
}
