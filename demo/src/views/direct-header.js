import {html} from "../util";

export default function(info) {
  switch (this.accepts("html", "json", "text")) {
    case "html":
      this.response.type = "text/html; charset=utf-8";
      this.body = html`${info.message}`;
      return;
    case "json":
    this.response.type = "application/json; charset=utf-8";
      this.body = JSON.stringify(info);
      return;
    default:
      this.response.type = "text/plain; charset=utf-8";
      this.body = info.message;
      return;
  }
}
