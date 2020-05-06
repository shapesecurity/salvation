package com.shapesecurity.salvation2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Pattern;


public class Directive {
	public static Predicate<String> containsNonDirectiveCharacter = Pattern.compile("[" + Constants.WHITESPACE_CHARS + ",;]").asPredicate();
	protected List<String> values;

	protected static DirectiveErrorConsumer wrapManipulationErrorConsumer(ManipulationErrorConsumer errors) {
		return (severity, message, valueIndex) -> {
			switch (severity) {
				case Info:
					errors.add(ManipulationErrorConsumer.Severity.Info, message);
					break;
				case Warning:
					errors.add(ManipulationErrorConsumer.Severity.Warning, message);
					break;
				case Error:
					throw new RuntimeException(message);
				default:
					throw new RuntimeException("unreachable: unknown severity " + severity);
			}
		};
	}

	protected void addValue(String value) {
		Policy.enforceAscii(value);
		if (containsNonDirectiveCharacter.test(value)) {
			throw new IllegalArgumentException("values must not contain whitespace, ',', or ';'");
		}
		if (value.isEmpty()) {
			throw new IllegalArgumentException("values must not be empty");
		}
		this.values.add(value);
	}

	public List<String> getValues() {
		return Collections.unmodifiableList(this.values);
	}

	protected Directive(List<String> values) {
		this.values = new ArrayList<>();
		for (String value : values) {
			// We use this API so we get the validity checks
			this.addValue(value);
		}
	}

	protected void removeValueIgnoreCase(String value) {
		String lowcaseValue = value.toLowerCase(Locale.ENGLISH);
		// Could we use some fancy data structure to avoid the linear indexing here? Yes, probably. But in practice these are short lists, and iterating them is not that expensive.
		ArrayList<String> copy = new ArrayList<>(this.values.size());
		for (String existing : this.values) {
			if (!existing.toLowerCase(Locale.ENGLISH).equals(lowcaseValue)) {
				copy.add(existing);
			}
		}
		this.values = copy;
	}


	@FunctionalInterface
	public interface DirectiveErrorConsumer {
		void add(Policy.Severity severity, String message, int valueIndex); // index = -1 for errors not pertaining to a value

		DirectiveErrorConsumer ignored = (severity, message, valueIndex) -> {};
	}

	@FunctionalInterface
	public interface ManipulationErrorConsumer {
		void add(Severity severity, String message);

		ManipulationErrorConsumer ignored = (severity, message) -> {};

		// Info: strictly informative
		// Warning: it matches the grammar, but is meaningless, duplicated, or otherwise problematic
		enum Severity { Info, Warning }
	}
}
