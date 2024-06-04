import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./API/authRouter.js";
import postRouter from "./API/postRouter.js";
import bodyParser from "body-parser";

const createServer = () => {
  const app = express();
  app.use(bodyParser.json());
  app.use(express.json());
  app.use(cookieParser());
  app.use("/auth", authRouter);
  app.use("/post", postRouter);

  app.use((error, req, res, next) => {
    error.statusCode = error.statusCode || 500;
    error.status = error.status || "error";
    res.status(error.statusCode).json({
      status: error.statusCode,
      message: error.message,
    });
  });

  return app;
};

export default createServer;