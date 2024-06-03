import express from "express";
import cookieParser from 'cookie-parser';
import authRouter from "./API/authRouter.js";
import postRouter from "./API/postRouter.js";
import bodyParser from "body-parser";

const PORT = process.env.PORT || 8000;

const StartServer = async () => {
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

  app
    .listen(PORT, () => {
      console.log(`listening to port ${PORT}`);
    })
    .on("error", (err) => {
      console.log(err);
      process.exit();
    });
};

StartServer();
