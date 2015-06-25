/*global $*/
/*eslint quotes: [1, "single"]*/
$(function () {
  'use strict';

  // TODO: add handler for fetchHeader form

  $('form[action="/directHeader"]').on('submit', function (evt) {
    evt.preventDefault();

    var cspType = $('select[name="headerName[]"]').val(),
     cspString = $('input[name="headerValue[]"]').val();

    $.ajax('/directHeader', {
      headers: {
        'Accept': 'application/json'
      },
      data: {
        'headerName[]': cspType,
        'headerValue[]': cspString
      },
      success: function (response) {
        $('#output').text(response.message);

        // TODO: add error/success class to output div
        // response.error
      }
    });
  });
});
