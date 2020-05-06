package com.shapesecurity.salvation2;

import java.util.Locale;
import java.util.Objects;

public class TestBase {
	Policy.PolicyListErrorConsumer throwIfPolicyListError = (severity, message, policyIndex, directiveIndex, valueIndex) -> {
		throw new RuntimeException(new PolicyListError(severity, message, policyIndex, directiveIndex, valueIndex).toString());
	};

	Policy.PolicyErrorConsumer throwIfPolicyError = (severity, message, directiveIndex, valueIndex) -> {
		throw new RuntimeException(new PolicyError(severity, message, directiveIndex, valueIndex).toString());
	};

	Directive.DirectiveErrorConsumer throwIfDirectiveError = (severity, message, valueIndex) -> {
		throw new RuntimeException(new DirectiveError(severity, message, valueIndex).toString());
	};

	Directive.ManipulationErrorConsumer throwIfManipulationError = (severity, message) -> {
		throw new RuntimeException(new ManipulationError(severity, message).toString());
	};

	static void inTurkey(Runnable r) {
		Locale current = Locale.getDefault();
		try {
			// In Turkey, "I" lowercases to "ı". This test enforces that we're doing ASCII-case-insensitive comparisons, rather than locale-specific comparisons.
			Locale.setDefault(new Locale("tr", "TR"));
			r.run();
		} finally {
			Locale.setDefault(current);
		}
	}

	protected static PolicyListError e(Policy.Severity severity, String message, int policyIndex, int directiveIndex, int valueIndex) {
		return new PolicyListError(severity, message, policyIndex, directiveIndex, valueIndex);
	}

	protected static PolicyError e(Policy.Severity severity, String message, int directiveIndex, int valueIndex) {
		return new PolicyError(severity, message, directiveIndex, valueIndex);
	}

	protected static DirectiveError e(Policy.Severity severity, String message, int valueIndex) {
		return new DirectiveError(severity, message, valueIndex);
	}

	protected static ManipulationError e(Directive.ManipulationErrorConsumer.Severity severity, String message) {
		return new ManipulationError(severity, message);
	}

	static class PolicyListError {
		final Policy.Severity severity;
		final String message;
		final int policyIndex;
		final int directiveIndex;
		final int valueIndex;

		PolicyListError(Policy.Severity severity, String message, int policyIndex, int directiveIndex, int valueIndex) {
			this.severity = severity;
			this.message = message;
			this.policyIndex = policyIndex;
			this.directiveIndex = directiveIndex;
			this.valueIndex = valueIndex;
		}

		@Override
		public String toString() {
			return "(" + this.severity.name() + ") " + this.message + " at policy " + this.policyIndex + " at directive " + this.directiveIndex + " at value " + this.valueIndex;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			PolicyListError that = (PolicyListError) o;
			return policyIndex == that.policyIndex &&
					directiveIndex == that.directiveIndex &&
					valueIndex == that.valueIndex &&
					severity == that.severity &&
					message.equals(that.message);
		}

		@Override
		public int hashCode() {
			return Objects.hash(severity, message, policyIndex, directiveIndex, valueIndex);
		}
	}

	static class PolicyError {
		final Policy.Severity severity;
		final String message;
		final int directiveIndex;
		final int valueIndex;

		PolicyError(Policy.Severity severity, String message, int directiveIndex, int valueIndex) {
			this.severity = severity;
			this.message = message;
			this.directiveIndex = directiveIndex;
			this.valueIndex = valueIndex;
		}

		@Override
		public String toString() {
			return "(" + this.severity.name() + ") " + this.message + " at directive " + this.directiveIndex + " at value " + this.valueIndex;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			PolicyError that = (PolicyError) o;
			return directiveIndex == that.directiveIndex &&
					valueIndex == that.valueIndex &&
					severity == that.severity &&
					message.equals(that.message);
		}

		@Override
		public int hashCode() {
			return Objects.hash(severity, message, directiveIndex, valueIndex);
		}
	}

	static class DirectiveError {
		final Policy.Severity severity;
		final String message;
		final int valueIndex;

		DirectiveError(Policy.Severity severity, String message, int valueIndex) {
			this.severity = severity;
			this.message = message;
			this.valueIndex = valueIndex;
		}

		@Override
		public String toString() {
			return "(" + this.severity.name() + ") " + this.message + " at value " + this.valueIndex;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			DirectiveError that = (DirectiveError) o;
			return valueIndex == that.valueIndex &&
					severity == that.severity &&
					message.equals(that.message);
		}

		@Override
		public int hashCode() {
			return Objects.hash(severity, message, valueIndex);
		}
	}

	static class ManipulationError {
		final Directive.ManipulationErrorConsumer.Severity severity;
		final String message;

		ManipulationError(Directive.ManipulationErrorConsumer.Severity severity, String message) {
			this.severity = severity;
			this.message = message;
		}

		@Override
		public String toString() {
			return "(" + this.severity.name() + ") " + this.message;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			ManipulationError that = (ManipulationError) o;
			return severity == that.severity &&
					message.equals(that.message);
		}

		@Override
		public int hashCode() {
			return Objects.hash(severity, message);
		}
	}

}
