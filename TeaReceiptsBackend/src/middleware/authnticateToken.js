import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_SECRET } from "../Config/index.js";
function authenticateToken(req, res, next) {
  const token = req.cookies.accessToken;
  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized - No token provided" });
  }
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

export default authenticateToken;
