import React from 'react';
import { Button } from 'react-bootstrap';

const Footer = () => {
  const viewLicenses = () => {
    window.location.pathname = '/licenses.json';
  };
  return (
    <footer role="contentinfo" className="pb-4">
      <p>
        <a href="https://github.com/shapesecurity/salvation/issues">Send your feedback</a>!
      </p>
      <p>
          CSP Validator was built by Sergey Shekyan, Michael Ficarra, Lewis Ellis,
          Ben Vinegar, and the fine folks at{' '}
        <a href="https://f5.com">F5, Inc.</a>.
      </p>
      <p>
          Powered by{' '}
        <a href="https://github.com/shapesecurity/salvation">Salvation</a>{' '}
          v3.0.1, a Java library for working with CSP policies.
      </p>
      <Button variant="link" className="p-0" onClick={viewLicenses}>View Licenses</Button>
    </footer>
  );
};
export { Footer };
