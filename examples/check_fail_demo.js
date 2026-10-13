// Demo script: request returns HTTP 200, but check expects 234 so the check fails.
// Use this to see how check failures are reported (e.g. summary, outputs).

import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 1,
  iterations: 1,
};

export default function () {
  const res = http.get('https://httpbin.org/status/20000');
  check(res, {
    'status is 234': (r) => r.status === 234,
  });
}
