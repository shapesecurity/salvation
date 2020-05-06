package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Directive;
import com.shapesecurity.salvation2.Policy;
import com.shapesecurity.salvation2.Values.MediaType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class PluginTypesDirective extends Directive {
	private List<MediaType> mediaTypes = new ArrayList<>();

	public PluginTypesDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);

		int index = 0;
		for (String token : values) {
			Optional<MediaType> type = MediaType.parseMediaType(token);
			if (type.isPresent()) {
				this._addMediaType(type.get(), index, errors);
			} else {
				errors.add(Policy.Severity.Error, "Expecting media-type but found \"" + token + "\"", index);
			}
		}

		// Note that empty lists are allowed: https://github.com/w3c/webappsec-csp/pull/374
	}

	private boolean _addMediaType(MediaType type, int index, DirectiveErrorConsumer errors) {
		if (this.mediaTypes.contains(type)) {
			errors.add(Policy.Severity.Warning, "Duplicate media type " + type.toString(), index);
			return false;
		} else {
			if (type.type.equals("*") || type.subtype.equals("*")) {
				errors.add(Policy.Severity.Warning, "Media types can only be matched literally. Make sure using `*` is not an oversight.", index);
			}
			this.mediaTypes.add(type);
			return true;
		}
	}

	public List<MediaType> getMediaTypes() {
		return Collections.unmodifiableList(this.mediaTypes);
	}

	public void addMediaType(MediaType type, ManipulationErrorConsumer errors) {
		if (this._addMediaType(type, -1, wrapManipulationErrorConsumer(errors))) {
			this.addValue(type.toString());
		}
	}

	public boolean removeMediaType(MediaType type) {
		if (!this.mediaTypes.contains(type)) {
			return false;
		}
		this.mediaTypes.remove(type);
		this.removeValueIgnoreCase(type.toString());
		return true;
	}
}
