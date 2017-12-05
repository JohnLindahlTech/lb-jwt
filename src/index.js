import assert from 'assert';
import Debug from 'debug';
import { ExtractJwt } from 'passport-jwt';
import jwt from 'jsonwebtoken';

const debug = Debug('lb-jwt');

export const tokenExtractor = ExtractJwt.fromExtractors([
  ExtractJwt.fromAuthHeaderAsBearerToken(),
  ExtractJwt.fromUrlQueryParameter('access_token'),
]);

export function verifyJWT(secret, token){
  return new Promise((resolve, reject) => {
    jwt.verify(token, secret, (error, payload) => {
      if (error) {
        return reject(error);
      }
      return resolve(payload);
    });
  });
}

export function attachUser(req, user){
  req.user = user;
}

export async function requestHandler(req, res, options){
  const token = tokenExtractor(req);
  if(!token){
    return;
  }
  const payload = await verifyJWT(options.secret, token);
  attachUser(req, payload);
}

function middleware(options = {}){
  assert(typeof options.jwtSecret === 'string', 'Must supply options.jwtSecret as a string');

  return (req, res, next) => {
    requestHandler(req, res, options)
      .then(() => next())
      .catch(error => next(error))

  }
}

export default middleware;
