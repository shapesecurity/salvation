package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Policy;

import java.util.List;
import java.util.Locale;

public class FrameAncestorsDirective extends HostSourceDirective {
	public FrameAncestorsDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);

		int index = 0;
		for (String token : values) {
			String lowcaseToken = token.toLowerCase(Locale.ENGLISH);
			this._addHostOrSchemeDuringConstruction(token, lowcaseToken, "ancestor-source", index, errors);
		}

		if (this.none != null && values.size() > 1) {
			errors.add(Policy.Severity.Error, "'none' must not be combined with any other ancestor-source", index);
		}

		if (values.isEmpty()) {
			errors.add(Policy.Severity.Error, "Ancestor-source lists cannot be empty (use 'none' instead)", -1);
		}
	}
}
