import React from 'react';
import { shape, string, number } from 'prop-types';
import { Tooltip, OverlayTrigger, CardHeader, Button, ButtonToolbar, ButtonGroup } from 'react-bootstrap';
import cspList from '../csp-list';

const PolicyBreakdown = ({ policy }) => {

  // Returns an array of arrays of directive name and value for each policy.
  const directives = policy.policy.split(';').map(s => s.trim()).filter(Boolean).map(d => d.trim().split(' '));

  const getCSPDescription = directiveName => cspList[directiveName] ?? 'Unknown directive';

  return (
    <CardHeader>
      <ButtonToolbar>
        {
          directives.map(([directiveName, ...directiveValues], i) => (
            <ButtonGroup className="me-2" key={i}>
              {/* Directive Name */}
              <OverlayTrigger id={i} overlay={
                // fixed position to stop the scrollbar from momentally showing up, thus making the page jump around.
                <Tooltip style={{ position: 'fixed' }} placement="top">{getCSPDescription(directiveName)}</Tooltip>
              }>
                <Button className="text-break" style={{ cursor: 'help' }} variant="primary" data-bs-toggle="tooltip" data-bs-placement="top" title={directiveName}>
                  {directiveName}
                </Button>
              </OverlayTrigger>

              {/* Directive Values */}
              { directiveValues.length > 0 &&
                <Button className="text-break" style={{ cursor: 'default' }} variant="info" data-bs-toggle="tooltip" data-bs-placement="top" title={directiveValues.join(' ')}>
                  {directiveValues.join(' ')}
                </Button>
              }

              {/* Directive Separator */}
              {
                i !== directives.length - 1 &&
                <Button title="directive separator" style={{ cursor: 'default' }} variant="secondary">;</Button>
              }
            </ButtonGroup>
          ))
        }
      </ButtonToolbar>
    </CardHeader>
  );
};

PolicyBreakdown.propTypes = {
  policy: shape({
    id: number.isRequired,
    policy: string.isRequired,
  }).isRequired,
};

export { PolicyBreakdown };
