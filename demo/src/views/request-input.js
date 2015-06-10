import {html} from "../util";

export default function() {
  this.response.type = "text/html; charset=utf-8";
  this.body = html`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CSP Header Inspector and Validator</title>
    <style>
      body {
        zoom: 200%;
        padding: 2em;
      }
      form p {
        display: flex;
      }
      form input {
        flex: 1;
        min-width: 6em;
      }
      form button {
        width: 3em;
      }
      form button, form select, form input {
        margin: 0 0.2em;
        font-size: 1em;
      }
      .or {
        text-align: center;
        font-size: x-large;
      }
    </style>
  </head>
  <body>
    <form action="/fetchHeader">
      <p>
        <input type="url" name="url" placeholder="https://..." />
        <button>Go</button>
      </p>
    </form>
    <p class="or"> OR </p>
    <form action="/directHeader">
      <p>
        <select name="headerName[]">
          <option>Content-Security-Policy:</option>
          <option>Content-Security-Policy-Report-Only:</option>
        </select>
        <input type="text" name="headerValue[]" width="120" />
        <button>Go</button>
      </p>
    </form>
  </body>
</html>`;
}
