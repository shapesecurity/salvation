import {html} from "../util";

export default function(info) {
  this.response.type = "application/json; charset=utf-8";
  this.response.status = 204;   
}
