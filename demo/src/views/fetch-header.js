import {html} from "../util";

export default function(info) {
  switch (this.accepts("html", "json", "text")) {
    case "html":
      this.response.type = "text/html; charset=utf-8";
      this.body = html`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CSP Header Inspector and Validator</title>
    <style>
    </style>
  </head>
  <body>
  ${info.message}
  </body>
</html>`;
      return;
    case "json":
      // TODO: design a JSON API
      this.body = info;
      return;
    default:
      this.body = info.message;
      return;
  }
}
