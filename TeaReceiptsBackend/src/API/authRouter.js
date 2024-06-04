import express from "express";
import AuthService from "../Services/AuthenticationService.js";
const authRouter = express();

const authService = new AuthService();
authRouter.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const response = await authService.signup({ name, email, password });
    return res.json(response);
  } catch (err) {
    res
      .status(err.statusCode || 500)
      .json({ status: "fail", message: err.message });
  }
});

authRouter.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const response = await authService.signin({ email, password });
    const { accessToken, refreshToken } = response;
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: true, sameSite: 'strict' });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
    return res.json(response);
  } catch (err) {
    res
      .status(err.statusCode || 500)
      .json({ status: "fail", message: err.message });
  }
});

authRouter.post("/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
      return res.status(403).json({ message: 'Refresh token not provided' });
    }
    const response = await authService.refreshToken(refreshToken);
    return res.json(response);
  } catch (error) {
    console.log(error);
    return res.status(403).json({ message: 'Invalid refresh token' });
  }
});

authRouter.put("/passwordRecovery", async (req, res) => {
  try {
    const { email, password } = req.body;
    const response = await authService.passwordRecovery({ email, password });
    return res.json(response);
  } catch (err) {
    res
      .status(err.statusCode || 500)
      .json({ status: "fail", message: err.message });
  }
});

export default authRouter;
