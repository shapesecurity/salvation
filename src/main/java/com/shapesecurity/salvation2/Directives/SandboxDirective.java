package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Directive;
import com.shapesecurity.salvation2.Policy;

import java.util.List;
import java.util.Locale;

public class SandboxDirective extends Directive {

	private boolean allowDownloads = false;
	private boolean allowForms = false;
	private boolean allowModals = false;
	private boolean allowOrientationLock = false;
	private boolean allowPointerLock = false;
	private boolean allowPopups = false;
	private boolean allowPopupsToEscapeSandbox = false;
	private boolean allowPresentation = false;
	private boolean allowSameOrigin = false;
	private boolean allowScripts = false;
	private boolean allowStorageAccessByUserActivation = false;
	private boolean allowTopNavigation = false;
	private boolean allowTopNavigationByUserActivation = false;

	public SandboxDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);

		int index = 0;
		for (String token : values) {
			// HTML attribute keywords are ascii-case-insensitive: https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#keywords-and-enumerated-attributes
			String lowcaseToken = token.toLowerCase(Locale.ENGLISH);
			switch (lowcaseToken) {
				case "allow-downloads":
					if (!this.allowDownloads) {
						this.allowDownloads = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-downloads", index);
					}
					break;
				case "allow-forms":
					if (!this.allowForms) {
						this.allowForms = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-forms", index);
					}
					break;
				case "allow-modals":
					if (!this.allowModals) {
						this.allowModals = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-modals", index);
					}
					break;
				case "allow-orientation-lock":
					if (!this.allowOrientationLock) {
						this.allowOrientationLock = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-orientation-lock", index);
					}
					break;
				case "allow-pointer-lock":
					if (!this.allowPointerLock) {
						this.allowPointerLock = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-pointer-lock", index);
					}
					break;
				case "allow-popups":
					if (!this.allowPopups) {
						this.allowPopups = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups", index);
					}
					break;
				case "allow-popups-to-escape-sandbox":
					if (!this.allowPopupsToEscapeSandbox) {
						this.allowPopupsToEscapeSandbox = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups-to-escape-sandbox", index);
					}
					break;
				case "allow-presentation":
					if (!this.allowPresentation) {
						this.allowPresentation = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-presentation", index);
					}
					break;
				case "allow-same-origin":
					if (!this.allowSameOrigin) {
						this.allowSameOrigin = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-same-origin", index);
					}
					break;
				case "allow-scripts":
					if (!this.allowScripts) {
						this.allowScripts = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-scripts", index);
					}
					break;
				case "allow-storage-access-by-user-activation":
					if (!this.allowStorageAccessByUserActivation) {
						this.allowStorageAccessByUserActivation = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-storage-access-by-user-activation", index);
					}
					break;
				case "allow-top-navigation":
					if (!this.allowTopNavigation) {
						this.allowTopNavigation = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation", index);
					}
					break;
				case "allow-top-navigation-by-user-activation":
					if (!this.allowTopNavigationByUserActivation) {
						this.allowTopNavigationByUserActivation = true;
					} else {
						errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation-by-user-activation", index);
					}
					break;
				default:
					if (token.startsWith("'")) {
						errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token + " - note that sandbox keywords do not have \"'\"s", index);
					} else {
						errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token, index);
					}
			}
			++index;
		}
	}


	public boolean allowDownloads() {
		return this.allowDownloads;
	}

	public void setAllowDownloads(boolean allowDownloads) {
		if (this.allowDownloads == allowDownloads) {
			return;
		}
		if (allowDownloads) {
			this.addValue("allow-downloads");
		} else {
			this.removeValueIgnoreCase("allow-downloads");
		}
		this.allowDownloads = allowDownloads;
	}


	public boolean allowForms() {
		return this.allowForms;
	}

	public void setAllowForms(boolean allowForms) {
		if (this.allowForms == allowForms) {
			return;
		}
		if (allowForms) {
			this.addValue("allow-forms");
		} else {
			this.removeValueIgnoreCase("allow-forms");
		}
		this.allowForms = allowForms;
	}


	public boolean allowModals() {
		return this.allowModals;
	}

	public void setAllowModals(boolean allowModals) {
		if (this.allowModals == allowModals) {
			return;
		}
		if (allowModals) {
			this.addValue("allow-modals");
		} else {
			this.removeValueIgnoreCase("allow-modals");
		}
		this.allowModals = allowModals;
	}


	public boolean allowOrientationLock() {
		return this.allowOrientationLock;
	}

	public void setAllowOrientationLock(boolean allowOrientationLock) {
		if (this.allowOrientationLock == allowOrientationLock) {
			return;
		}
		if (allowOrientationLock) {
			this.addValue("allow-orientation-lock");
		} else {
			this.removeValueIgnoreCase("allow-orientation-lock");
		}
		this.allowOrientationLock = allowOrientationLock;
	}


	public boolean allowPointerLock() {
		return this.allowPointerLock;
	}

	public void setAllowPointerLock(boolean allowPointerLock) {
		if (this.allowPointerLock == allowPointerLock) {
			return;
		}
		if (allowPointerLock) {
			this.addValue("allow-pointer-lock");
		} else {
			this.removeValueIgnoreCase("allow-pointer-lock");
		}
		this.allowPointerLock = allowPointerLock;
	}


	public boolean allowPopups() {
		return this.allowPopups;
	}

	public void setAllowPopups(boolean allowPopups) {
		if (this.allowPopups == allowPopups) {
			return;
		}
		if (allowPopups) {
			this.addValue("allow-popups");
		} else {
			this.removeValueIgnoreCase("allow-popups");
		}
		this.allowPopups = allowPopups;
	}


	public boolean allowPopupsToEscapeSandbox() {
		return this.allowPopupsToEscapeSandbox;
	}

	public void setAllowPopupsToEscapeSandbox(boolean allowPopupsToEscapeSandbox) {
		if (this.allowPopupsToEscapeSandbox == allowPopupsToEscapeSandbox) {
			return;
		}
		if (allowPopupsToEscapeSandbox) {
			this.addValue("allow-popups-to-escape-sandbox");
		} else {
			this.removeValueIgnoreCase("allow-popups-to-escape-sandbox");
		}
		this.allowPopupsToEscapeSandbox = allowPopupsToEscapeSandbox;
	}


	public boolean allowPresentation() {
		return this.allowPresentation;
	}

	public void setAllowPresentation(boolean allowPresentation) {
		if (this.allowPresentation == allowPresentation) {
			return;
		}
		if (allowPresentation) {
			this.addValue("allow-presentation");
		} else {
			this.removeValueIgnoreCase("allow-presentation");
		}
		this.allowPresentation = allowPresentation;
	}


	public boolean allowSameOrigin() {
		return this.allowSameOrigin;
	}

	public void setAllowSameOrigin(boolean allowSameOrigin) {
		if (this.allowSameOrigin == allowSameOrigin) {
			return;
		}
		if (allowSameOrigin) {
			this.addValue("allow-same-origin");
		} else {
			this.removeValueIgnoreCase("allow-same-origin");
		}
		this.allowSameOrigin = allowSameOrigin;
	}


	public boolean allowScripts() {
		return this.allowScripts;
	}

	public void setAllowScripts(boolean allowScripts) {
		if (this.allowScripts == allowScripts) {
			return;
		}
		if (allowScripts) {
			this.addValue("allow-scripts");
		} else {
			this.removeValueIgnoreCase("allow-scripts");
		}
		this.allowScripts = allowScripts;
	}


	public boolean allowStorageAccessByUserActivation() {
		return this.allowStorageAccessByUserActivation;
	}

	public void setAllowStorageAccessByUserActivation(boolean allowStorageAccessByUserActivation) {
		if (this.allowStorageAccessByUserActivation == allowStorageAccessByUserActivation) {
			return;
		}
		if (allowStorageAccessByUserActivation) {
			this.addValue("allow-storage-access-by-user-activation");
		} else {
			this.removeValueIgnoreCase("allow-storage-access-by-user-activation");
		}
		this.allowStorageAccessByUserActivation = allowStorageAccessByUserActivation;
	}


	public boolean allowTopNavigation() {
		return this.allowTopNavigation;
	}

	public void setAllowTopNavigation(boolean allowTopNavigation) {
		if (this.allowTopNavigation == allowTopNavigation) {
			return;
		}
		if (allowTopNavigation) {
			this.addValue("allow-top-navigation");
		} else {
			this.removeValueIgnoreCase("allow-top-navigation");
		}
		this.allowTopNavigation = allowTopNavigation;
	}


	public boolean allowTopNavigationByUserActivation() {
		return this.allowTopNavigationByUserActivation;
	}

	public void setAllowTopNavigationByUserActivation(boolean allowTopNavigationByUserActivation) {
		if (this.allowTopNavigationByUserActivation == allowTopNavigationByUserActivation) {
			return;
		}
		if (allowTopNavigationByUserActivation) {
			this.addValue("allow-top-navigation-by-user-activation");
		} else {
			this.removeValueIgnoreCase("allow-top-navigation-by-user-activation");
		}
		this.allowTopNavigationByUserActivation = allowTopNavigationByUserActivation;
	}
}
