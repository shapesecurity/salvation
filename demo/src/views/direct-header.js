import {html} from "../util";

export default function(policyResult) {
  switch (this.accepts("html", "json", "text")) {
    case "html":
      this.response.type = "text/html; charset=utf-8";
      this.body = html`${policyResult}`;
      return;
    case "json":
      this.body = { message: policyResult };
      return;
    default:
      this.body = policyResult;
      return;
  }
}
