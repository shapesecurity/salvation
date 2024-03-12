import React, { useState } from 'react';
import { Toast } from 'react-bootstrap';
import { string, func, number } from 'prop-types';

const ErrorToast = ({ stack, dismiss, id }) => {
  const [show, setShow] = useState(true);

  const removeError = () => {
    setShow(false);
    dismiss({ stack, id });
  };

  return (
    <Toast bg="danger" onClose={removeError} onExit={removeError} show={show} delay={15000} autohide={true}>
      <Toast.Header>
        <strong className="me-auto">Error</strong>
      </Toast.Header>
      <Toast.Body>
        <pre>{stack}</pre>
      </Toast.Body>
    </Toast>
  );
};

ErrorToast.propTypes = {
  stack: string.isRequired,
  id: number.isRequired,
  dismiss: func.isRequired,
};

export { ErrorToast };
