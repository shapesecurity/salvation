import React, { memo, useMemo, useReducer } from 'react';
import { shape, arrayOf, number, string } from 'prop-types';
import { Card, CardBody, ListGroup, ListGroupItem, Stack } from 'react-bootstrap';
import { PolicyBreakdown } from './PolicyBreakdown';
import { ErrorToast } from './ErrorToast';

const errorReducer = (prevErrors, action) => {
  const matchingError = prevErrors.find(e => e.id === action.error.id && e.stack === action.error.stack);
  if (matchingError) return prevErrors;
  if (action.type === 'add') {
    return [...prevErrors, action.error];
  } else if (action.type === 'remove') {
    return prevErrors.filter(e => e.id !== action.error.id);
  }
  return prevErrors;
};

const OutputPanel = memo(({ policies }) => {
  const [errors, setErrors] = useReducer(errorReducer, []);

  const validationResults = [];

  useMemo(() => {
    const errorsToSet = [];
    policies.filter(({ policy }) => policy !== '').forEach(({ policy, id }) => {
      try {
        const result = window.getErrorsForSerializedCSP(policy);
        if (!result) {
          validationResults.push({ id, results: ['Valid'] });
        } else {
          validationResults.push({ id, results: result.split('\n').map(r => !r ? 'Valid' : r) });
        }
      } catch (e) {
        errorsToSet.push({ id, error: e });
      }
    });
    errorsToSet.forEach(error => setErrors({ type: 'add', error }));
    return errorsToSet;
  }, [policies]);

  const findPolicyById = id => policies.find(p => p.id === id);
  const hasGivenStatus = (directive, givenStatus) => directive.toLowerCase().startsWith(givenStatus);
  const calculateBorder = index => {
    if (index === 0 && validationResults.length > 1) {
      return 'rounded-bottom-0';
    } else if (index === validationResults.length - 1 && validationResults.length > 1) {
      return 'rounded-top-0 border-top-0';
    } else if (index > 0 && index < validationResults.length - 1) {
      return 'rounded-0 border-top-0';
    }
    return '';
  };

  const getVariantByResult = result => {
    let parseStatusClass = null;

    if (hasGivenStatus(result, 'warning')) {
      parseStatusClass = 'warning';
    }
    if (hasGivenStatus(result, 'error')) {
      parseStatusClass = 'danger';
    }
    if (hasGivenStatus(result, 'info')) {
      parseStatusClass = 'info';
    }

    return parseStatusClass || 'success';
  };

  const results = useMemo(() => (validationResults.map(({ results: rslts, id }, i) => (
    <Card className={calculateBorder(i)} key={i}>
      <PolicyBreakdown policy={findPolicyById(id)} />
      <CardBody>
        <Stack orientation="vertical">
          <ListGroup as="ol" numbered key={i}>
            {rslts.map((r, j) => (
              <ListGroupItem as="li" variant={getVariantByResult(r)} key={j}>
                {r}
              </ListGroupItem>
            ))}
          </ListGroup>
        </Stack>
      </CardBody>
    </Card>
  ))), [policies]);

  const dismissError = error => {
    setErrors({ type: 'remove', error });
  };

  return (
    <>
      {errors.map(({ error, id }) => (
        <ErrorToast key={id} id={id} stack={error.stack} dismiss={dismissError} />
      ))}
      {results}
    </>
  );
});

OutputPanel.displayName = 'OutputPanel';

OutputPanel.propTypes = {
  policies: arrayOf(shape({
    id: number.isRequired,
    policy: string.isRequired,
  })).isRequired,
  validationResults: arrayOf(
    shape({
      id: number.isRequired,
      results: arrayOf(string),
    }).isRequired,
  ).isRequired,
};

export { OutputPanel };
