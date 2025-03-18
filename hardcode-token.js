const jwt = require('jsonwebtoken');
const JWT_SECRET_KEY = "ce685757f0d508e8c218a81a691971ca561b506e";

const token = jwt.sign(
    {
      "claims.jwt.hasura.io": {
        "x-hasura-role": "admin",
      } 
    },
    JWT_SECRET_KEY,
    { expiresIn: "30d" }
);

console.log('Hardcoded JWT Token:', token);