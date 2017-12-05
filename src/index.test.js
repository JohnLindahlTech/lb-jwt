import test from 'ava';
import {
  verifyJWT,
  attachUser,
  requestHandler,
  tokenExtractor,
} from './index';
import jwt from 'jsonwebtoken';

const user = {
  name: 'John Doe',
  sub: '1234567890',
  iat: 1512495411,
};
const secret = 'secret';

test('verifyJWT should return the payload', async (t) => {
  const token = jwt.sign(user, secret);
  const result = await verifyJWT(secret, token);
  t.deepEqual(result, user);
});

test('attachUser should be able to attach a user', (t) => {
  const req = {};
  attachUser(req, user)
  t.deepEqual(req, { user })
});

test('tokenExtractor should be able to get the jwt token from bearer', t => {
  const req = {
    headers: {
      authorization: 'Bearer token',
    },
    url: '',
  };
  t.is(tokenExtractor(req), 'token');
});

test('tokenExtractor should be able to get the jwt token from url query param', t => {
  const req = {
    headers: {},
    url: '/not/used?access_token=token'
  };
  t.is(tokenExtractor(req), 'token');
});


test('requestHandler should be able to create a user property', async (t) => {
  const token = jwt.sign(user, secret);
  const req = {
    headers: {
      authorization: `Bearer ${token}`,
    }
  };
  const res = {};
  await requestHandler(req, res, { secret });
  t.deepEqual(req.user, user);
});

test('requestHandler should do nothing if jwt is missing.', async (t) => {
  const token = jwt.sign(user, secret);
  const req = {
    headers: {
    },
    url: '',
  };
  const res = {};
  await requestHandler(req, res, { secret });
  t.is(typeof req.user, 'undefined');
});
