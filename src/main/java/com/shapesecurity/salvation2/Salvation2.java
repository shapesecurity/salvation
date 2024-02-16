package com.shapesecurity.salvation2;

import org.teavm.jso.JSBody;

public class Salvation2 {
	public static void main(String[] args) {
		initParseList();
		initParseSingle();
	}

	public static String getErrorsForSerializedCSPList(String policyText) {
		StringBuilder errorMessages = new StringBuilder();
		Policy.parseSerializedCSPList(policyText, (severity, message, policyIndex, directiveIndex, valueIndex) -> {
			errorMessages.append(severity.name())
				.append(" at directive ")
				.append(directiveIndex)
				.append(valueIndex == -1 ? "" : " at value " + valueIndex)
				.append(": ")
				.append(message)
				.append("\n");
		});
		return errorMessages.toString().trim();
	}

	public static String getErrorsForSerializedCSP(String policyText) {
		StringBuilder errorMessages = new StringBuilder();

		Policy.parseSerializedCSP(policyText, (severity, message, directiveIndex, valueIndex) -> {
			errorMessages.append(severity.name())
				.append(" at directive ")
				.append(directiveIndex)
				.append(valueIndex == -1 ? "" : " at value " + valueIndex)
				.append(": ")
				.append(message)
				.append("\n");
		});
		return errorMessages.toString().trim();
	}

	@JSBody(params = {}, script =
		"(window || globalThis).getErrorsForSerializedCSPList = (policyText) => {\n" +
		"return javaMethods.get('com.shapesecurity.salvation2.Salvation2.getErrorsForSerializedCSPList(Ljava/lang/String;)Ljava/lang/String;').invoke(policyText)\n" +
		"}")
	static native void initParseList();

	@JSBody(params = {}, script =
		"(window || globalThis).getErrorsForSerializedCSP = (policyText) => {\n" +
			"return javaMethods.get('com.shapesecurity.salvation2.Salvation2.getErrorsForSerializedCSP(Ljava/lang/String;)Ljava/lang/String;').invoke(policyText)\n" +
			"}")
	static native void initParseSingle();
}

