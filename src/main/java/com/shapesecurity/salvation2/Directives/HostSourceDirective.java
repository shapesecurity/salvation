package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Constants;
import com.shapesecurity.salvation2.Directive;
import com.shapesecurity.salvation2.Policy;
import com.shapesecurity.salvation2.Values.Host;
import com.shapesecurity.salvation2.Values.Scheme;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

public abstract class HostSourceDirective extends Directive {
	private static final String NONE_SRC = "'none'";
	private static final String SELF_SRC = "'self'";
	protected List<Scheme> schemes = new ArrayList<>();
	protected List<Host> hosts = new ArrayList<>();
	protected boolean star = false;
	protected boolean self = false;

	protected String none = null;

	protected HostSourceDirective(List<String> values) {
		super(values);
	}

	@Override
	protected void addValue(String value) {
		if (this.none != null) {
			super.removeValueIgnoreCase(NONE_SRC); // super so as to not immediately add it back
			this.none = null;
		}
		super.addValue(value);
	}

	@Override
	protected void removeValueIgnoreCase(String value) {
		super.removeValueIgnoreCase(value);
		if (this.values.isEmpty()) {
			this.values.add(NONE_SRC);
			this.none = NONE_SRC;
		}
	}

	protected <T> void removeValuesMatching(T value, Function<String, Optional<T>> parser) {
		ArrayList<String> copy = new ArrayList<>(this.values.size());
		for (String existing : this.values) {
			Optional<T> parsed = parser.apply(existing);
			if (!parsed.isPresent() || !parsed.get().equals(value)) {
				copy.add(existing);
			}
		}
		this.values = copy;
		if (this.values.isEmpty()) {
			this.values.add(NONE_SRC);
			this.none = NONE_SRC;
		}
	}

	void _addHostOrSchemeDuringConstruction(String token, String lowcaseToken, String kind, int index, DirectiveErrorConsumer errors) {
		if (lowcaseToken.equals(NONE_SRC)) {
			if (this.none == null) {
				this.none = token;
			}
		} else if (lowcaseToken.equals("*")) {
			// Technically this is just a specific kind of host-source, but it's worth handling explicitly
			if (!this.star) {
				this.star = true;
			} else {
				errors.add(Policy.Severity.Warning, "Duplicate " + kind + " *", index);
			}
		} else if (lowcaseToken.equals(SELF_SRC)) {
			if (!this.self) {
				this.self = true;
			} else {
				errors.add(Policy.Severity.Warning, "Duplicate " + kind + " 'self'", index);
			}
		} else {
			Optional<Scheme> asScheme = Scheme.parseScheme(token);
			if (asScheme.isPresent()) {
				this._addScheme(asScheme.get(), index, errors);
			} else {
				if (Constants.unquotedKeywordPattern.matcher(token).find()) {
					errors.add(Policy.Severity.Warning, "This host name is unusual, and likely meant to be a keyword that is missing the required quotes: \'" + token + "\'.", index);
				}

				Optional<Host> asHost = Host.parseHost(token);
				if (asHost.isPresent()) {
					this._addHostSource(asHost.get(), index, errors);
				} else {
					errors.add(Policy.Severity.Error, "Unrecognized " + kind + " " + token, index);
				}
			}
		}
	}

	private boolean _addScheme(Scheme scheme, int index, DirectiveErrorConsumer errors) {
		if (this.schemes.contains(scheme)) {
			errors.add(Policy.Severity.Warning, "Duplicate scheme " + scheme, index);
			return false;
		} else {
			// TODO check if this subsumes or is subsumed by any existing scheme/host
			// NB we add it even if it subsumes or is subsumed by existing things, since it's still valid and not a duplicate
			this.schemes.add(scheme);
			return true;
		}
	}

	private boolean _addHostSource(Host source, int index, DirectiveErrorConsumer errors) {
		if (this.hosts.contains(source)) {
			errors.add(Policy.Severity.Warning, "Duplicate host " + source.toString(), index);
			return false;
		} else {
			// TODO check if this subsumes or is subsumed by any existing scheme/host
			this.hosts.add(source);
			return true;
		}
	}

	public boolean star() {
		return this.star;
	}

	public void setStar(boolean star) {
		if (this.star == star) {
			return;
		}
		if (star) {
			this.addValue("*");
		} else {
			this.removeValueIgnoreCase("*");
		}
		this.star = star;
	}

	public boolean self() {
		return this.self;
	}

	public void setSelf(boolean self) {
		if (this.self == self) {
			return;
		}
		if (self) {
			this.addValue(SELF_SRC);
		} else {
			this.removeValueIgnoreCase(SELF_SRC);
		}
		this.self = self;
	}

	public List<Scheme> getSchemes() {
		return Collections.unmodifiableList(this.schemes);
	}

	public void addScheme(Scheme scheme, ManipulationErrorConsumer errors) {
		if (this._addScheme(scheme, -1, wrapManipulationErrorConsumer(errors))) {
			this.addValue(scheme.toString());
		}
	}

	public boolean removeScheme(Scheme scheme) {
		if (!this.schemes.contains(scheme)) {
			return false;
		}
		this.schemes.remove(scheme);
		this.removeValueIgnoreCase(scheme.toString());
		return true;
	}


	public List<Host> getHosts() {
		return Collections.unmodifiableList(this.hosts);
	}

	public void addHost(Host host, ManipulationErrorConsumer errors) {
		if (host.equals(Host.STAR)) {
			if (this.star) {
				errors.add(ManipulationErrorConsumer.Severity.Warning, "Duplicate host *");
			} else {
				this.star = true;
				this.addValue("*");
			}
			return;
		}
		if (this._addHostSource(host, -1, wrapManipulationErrorConsumer(errors))) {
			this.addValue(host.toString());
		}
	}

	public boolean removeHost(Host host) {
		if (host.equals(Host.STAR)) {
			if (this.star) {
				this.setStar(false);
				return true;
			}
			return false;
		}
		if (!this.hosts.contains(host)) {
			return false;
		}
		this.hosts.remove(host);
		// Removing hosts is considerably more annoying than removing anything else, because they can have many representations.
		removeValuesMatching(host, Host::parseHost);
		return true;
	}
}
