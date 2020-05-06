package com.shapesecurity.salvation2;

import java.util.List;

public class PolicyList {
	public final List<Policy> policies;

	public PolicyList(List<Policy> policies) {
		this.policies = policies;
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();
		boolean first = true;
		for (Policy policy : this.policies) {
			if (!first) {
				out.append(", "); // The whitespace is not strictly necessary but is probably valuable
			}
			first = false;
			out.append(policy.toString());
		}
		return out.toString();
	}
}
