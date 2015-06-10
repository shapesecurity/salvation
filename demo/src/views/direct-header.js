import {html} from "../util";

export default function(info) {
  switch (this.accepts("html", "json", "text")) {
    case "html":
      this.response.type = "text/html; charset=utf-8";
      this.body = html`${info.message}`;
      return;
    case "json":
      this.body = info;
      return;
    default:
      this.body = info.message;
      return;
  }
}
