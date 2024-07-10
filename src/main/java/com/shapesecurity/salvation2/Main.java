package com.shapesecurity.salvation2;

public class Main {
	public static void main(String[] args) {
		if (args.length == 0) {
			throw new IllegalArgumentException("Please provide a comma separated list of policies.");
		}

		String policyText = String.join(",", args);

		PolicyList policies = Policy.parseSerializedCSPList(policyText, (severity, message, policyIndex, directiveIndex, valueIndex) -> {
			System.err.println(severity.name() + " at directive " + directiveIndex + (valueIndex == -1 ? "" : " at value " + valueIndex) + ": " + message);
		});

		System.out.println("Finished validating policies.");
	}
}
