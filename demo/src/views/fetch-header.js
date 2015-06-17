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
      this.response.type = "application/json; charset=utf-8";
      this.body = JSON.stringify(info);
      return;
    default:
      this.response.type = "text/plain; charset=utf-8";
      this.body = info.message;
      return;
  }
}
