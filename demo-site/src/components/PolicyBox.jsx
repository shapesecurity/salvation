import React from 'react';
import { element, func, number, string, shape, arrayOf } from 'prop-types';
import { FormLabel, InputGroup, Button, FormControl } from 'react-bootstrap';
import { ShuffleIcon } from '../icons/ShuffleIcon';

const PolicyBox = props => {
  const {
    AddOrRemovePolicyRowBtn,
    setPolicies,
    policies,
    boxId,
  } = props;

  let policy = policies.find(p => p.id === boxId)?.policy || '';

  const samplePolicies = [
    'plugin-types image/png; script-src \'unsafe-redirect\'',
    'plugin-types image/png application/pdf; sandbox',
    'default-src; script-src example.com; style-src example.net',
    'default-src \'self\'; script-src a',
    'style-src *:80',
    'img-src ftp://*',
    'script-src',
    'script-src \'self\'',
    'script-src example.com',
    'connect-src wss://*.example.com',
    'style-src https: \'self\'',
    'script-src \'sha512-vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==\'',
    'default-src \'nonce-5XVOskmSBTwHDfTMmfqnNpY2\'',
  ];

  const pickAPolicy = () => {
    policy = samplePolicies[Math.floor(Math.random() * samplePolicies.length)];
    setPolicies({ type: 'update', pId: boxId, updatedPolicy: policy });
  };

  const policyChangeHandler = e => {
    policy = e.target.value;
    setPolicies({ type: 'update', pId: boxId, updatedPolicy: policy });
  };

  return (
    <InputGroup className="mt-2">
      <Button title="pick a random policy" variant="info" onClick={pickAPolicy}>
        <ShuffleIcon />
      </Button>
      {AddOrRemovePolicyRowBtn}
      <FormLabel visuallyHidden htmlFor={`headerValue-${boxId}`}>
        Enter Content Security Policy:
      </FormLabel>
      <FormControl
        id={`headerValue-${boxId}`}
        placeholder="Enter a policy or generate a random one"
        autoComplete="off"
        value={policy}
        onChange={policyChangeHandler}
      />
    </InputGroup >
  );
};

PolicyBox.propTypes = {
  AddOrRemovePolicyRowBtn: element.isRequired,
  setPolicies: func.isRequired,
  boxId: number.isRequired,
  policies: arrayOf(shape({
    id: number.isRequired,
    policy: string.isRequired,
  })).isRequired,
};

export { PolicyBox };
