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
    <link href="/css/bootstrap.css" type="text/css" rel="stylesheet"/>
    <script src="/js/jquery.js"></script>
    <script src="/js/validator.js"></script>
  </head>
  <body>
    <form action="/fetchHeader">
      <div class="row">
        <div class="col-md-4">
          <input type="url" name="url" placeholder="https://..." class="form-control"/>
        </div>
        <div class="col-md-4">
          <button class="form-control">Go</button>
        </div>
      </div>
    </form>
    <p class="or"> OR </p>
    <form action="/directHeader">
      <div class="row">
        <div class="col-md-4">
          <select name="headerName[]" class="form-control">
            <option>Content-Security-Policy:</option>
            <option>Content-Security-Policy-Report-Only:</option>
          </select>
        </div>
        <div class="col-md-4">
          <input type="text" name="headerValue[]" width="120" class="form-control"/>
        </div>
        <div class="col-md-2">
          <button class="form-control">Go</button>
        </div>
      </div>
    </form>
    <!-- TODO: make this pretty -->
    <div id="output">
    </div>
  </body>
</html>`;
}
