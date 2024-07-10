package com.shapesecurity.salvation2;

import org.teavm.jso.JSBody;

public class Salvation2 {
	public static void main(String[] args) {
		initParseList();
		initParseSingle();
	}

	public static void parseSerializedCSPList(String policyText) {
		Policy.parseSerializedCSPList(policyText, (severity, message, policyIndex, directiveIndex, valueIndex) -> {
			System.err.println(severity.name() + " at directive " + directiveIndex + (valueIndex == -1 ? "" : " at value " + valueIndex) + ": " + message);
		});
	}

	public static void parseSerializedCSP(String policyText) {
		Policy.parseSerializedCSP(policyText, (severity, message, directiveIndex, valueIndex) -> {
			System.err.println(severity.name() + " at directive " + directiveIndex + (valueIndex == -1 ? "" : " at value " + valueIndex) + ": " + message);
		});
	}
	@JSBody(params={}, script=
		"(exports || window).parseSerializedCSPList = (policyText) => {\n" +
		"return javaMethods.get('com.shapesecurity.salvation2.Salvation2.parseSerializedCSPList(Ljava/lang/String;)V').invoke(policyText)\n" +
		"}")
	static native void initParseList();

	@JSBody(params={}, script=
		"(exports || window).parseSerializedCSP = (policyText) => {\n" +
			"return javaMethods.get('com.shapesecurity.salvation2.Salvation2.parseSerializedCSP(Ljava/lang/String;)V').invoke(policyText)\n" +
			"}")
	static native void initParseSingle();
}

