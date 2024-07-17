import React, { useReducer } from 'react';
import { Container } from 'react-bootstrap';
import { Footer } from './components/Footer';
import { CSPValidationForm } from './components/CSPValidationForm';
import { OutputPanel } from './components/OutputPanel';

const policyReducer = (currentPolicies, action) => {
  if (action.type === 'update') {
    const newPolicies = [...currentPolicies];
    const policyIndex = newPolicies.findIndex(p => p.id === action.pId);
    newPolicies[policyIndex].policy = action.updatedPolicy;
    return newPolicies;
  }
  if (action.type === 'add') {
    return [...currentPolicies, { id: action.pId, policy: '' }];
  }
  if (action.type === 'remove') {
    const newPolicies = [...currentPolicies];
    const policyIndex = newPolicies.findIndex(p => p.id === action.pId);
    newPolicies.splice(policyIndex, 1);
    return newPolicies;
  }
  if (action.type === 'overwriteAll') {
    return [...action.policies];
  }
  throw new Error(`Unknown action type: ${action.type}`);
};

const App = () => {
  window.main(); // Need this to initialize the CSP parsing functions.

  const [policies, setPolicies] = useReducer(policyReducer, [{ id: 0, policy: '' }]);

  return (
    <Container className="d-flex flex-column flex-grow-1">
      <main className="flex-grow-1">
        <h1 className="py-3 border-bottom">Content Security Policy (CSP) Validator</h1>
        <h2 className="pt-3">Validate/Manipulate CSP Strings</h2>
        <CSPValidationForm policies={policies} setPolicies={setPolicies} />
        <OutputPanel policies={policies} />
      </main>
      <hr />
      <Footer />
    </Container>
  );
};

export { App };
