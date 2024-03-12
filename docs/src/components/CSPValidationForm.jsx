import React, { useState, useEffect } from 'react';
import { arrayOf, func, string, shape, number } from 'prop-types';
import { Button, Card, CardBody, Col, Row } from 'react-bootstrap';
import { compressToBase64, compressToEncodedURIComponent, decompressFromBase64, decompressFromEncodedURIComponent } from 'lz-string';
import { PolicyBox } from './PolicyBox';
import { DashIcon } from '../icons/DashIcon';
import { PlusIcon } from '../icons/PlusIcon';

const CSPValidationForm = props => {
  const { policies, setPolicies } = props;
  // This is accounting for the first box which is not managed by state.
  const [boxId, setBoxId] = useState(1);

  const removePolicyBox = pId => {
    setPolicies({ type: 'remove', pId });
  };

  const removeAPolicyButton = id => (
    <Button variant="danger"
      title="remove a policy"
      onClick={() => {
        removePolicyBox(id);
      }}
    >
      <DashIcon />
    </Button>
  );

  // Adds another row of policy validation inputs with a remove button
  const addPolicyRow = () => {
    const incrementedBoxId = boxId + 1;
    setPolicies({ type: 'add', pId: incrementedBoxId });
    setBoxId(incrementedBoxId);
  };

  const AddPolicyRowBtn = (
    <Button
      variant="success"
      title="add a policy"
      onClick={addPolicyRow}
    >
      <PlusIcon />
    </Button>
  );

  // This expects a single string and each policy is on a new line.
  const setMultiplePolicies = unparsedPolicies => {
    const splitText = unparsedPolicies.split('\n');
    let newBoxId = 0;
    const newPolicies = splitText.filter(Boolean).map(p => ({ id: newBoxId++, policy: p.trim() }));
    setPolicies({ type: 'overwriteAll', policies: newPolicies });
    setBoxId(newBoxId);
    // Skip the first input box with .slice(1) since it's not managed by state.
  };

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const policyParam = urlParams.get('policy');
    const policyLzParam = urlParams.get('policy_lz');
    let policiesToSet;
    if (policyParam != null) {
      policiesToSet = policyParam;
    } else if (policyLzParam != null) {
      policiesToSet = decompressFromBase64(decompressFromEncodedURIComponent(policyLzParam));
    }
    if (policiesToSet) {
      setMultiplePolicies(policiesToSet);
    }
  }, []);

  useEffect(() => {
    const allTogetherNow = policies.map(({ policy }) => policy).join('\n');
    const compressed = compressToEncodedURIComponent(compressToBase64(allTogetherNow));
    const url = `${window.location.pathname}?policy_lz=${compressed}`;
    history.replaceState(null, null, url);
  }, [policies]);

  return (
    <Card className="mb-3">
      <CardBody
        as="form"
        onSubmit={e => {
          e.preventDefault();
        }}
      >
        <Row>
          <Col md={12}>
            <PolicyBox
              AddOrRemovePolicyRowBtn={AddPolicyRowBtn}
              policies={policies}
              setPolicies={setPolicies}
              boxId={0}
            />
            {/* Splatting the array prevents mutating state, which is bad in React. */}
            {[...policies].slice(1).map(p => (
              <PolicyBox
                key={p.id}
                boxId={p.id}
                policies={policies}
                setPolicies={setPolicies}
                AddOrRemovePolicyRowBtn={removeAPolicyButton(p.id)}
              />
            ))}
          </Col>
        </Row>
      </CardBody>
    </Card>
  );
};

CSPValidationForm.propTypes = {
  setValidationResults: func.isRequired,
  policies: arrayOf(
    shape({
      id: number.isRequired,
      policy: string.isRequired,
    }),
  ).isRequired,
  setPolicies: func.isRequired,
};

export { CSPValidationForm };
