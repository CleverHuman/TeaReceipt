import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } from "../Config/index.js";


export const generateAccessToken = (user) => {
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};

export const generateRefreshToken = (user) => {
  return jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

export const generateTokenFromRefresh = (token) => {
  const user = jwt.verify(token, REFRESH_TOKEN_SECRET);
  return jwt.sign({
    id: user.id,
    name: user.name,
    email: user.email,
    username: user.username
  }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
} 