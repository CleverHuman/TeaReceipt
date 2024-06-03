import express from "express";
import PostService from "../Services/PostService.js";
import authenticateToken from "../middleware/authnticateToken.js";
import { upload } from "../middleware/upload.js";
const postRouter = express();

const service = new PostService();

postRouter.post(
  "/createPost",
  authenticateToken,
  upload.array("images", 5),
  async (req, res, next) => {
    try {
      const { phone_number, city, caption, name } = req.body;
      const images = req.files.map((file) => file.path);
      const data = {
        phone_number: phone_number,
        city: city,
        caption: caption,
        userId: req.user.id,
        name: name,
        images: images,
      };
      const response = await service.CreatePost(data);
      return res.json(response);
    } catch (err) {
      res
        .status(err.statusCode || 500)
        .json({ status: "fail", message: err.message });
    }
  }
);

postRouter.delete(
  "/deletePost/:id",
  authenticateToken,
  async (req, res, next) => {
    try {
      const id = req.params.id;
      const response = await service.DeletePost(id);
      return res.json(response);
    } catch (err) {
      res
        .status(err.statusCode || 500)
        .json({ status: "fail", message: err.message });
    }
  }
);

postRouter.get("/getAllPosts", authenticateToken, async (req, res, next) => {
  try {
    const response = await service.GetAllPosts();
    return res.json(response);
  } catch (err) {
    res
      .status(err.statusCode || 500)
      .json({ status: "fail", message: err.message });
  }
});

postRouter.get(
  "/getAllPosts/:id",
  authenticateToken,
  async (req, res, next) => {
    const id = req.params.id;
    try {
      const response = await service.getPostByCurrentUser(id);
      return res.json(response);
    } catch (err) {
      res
        .status(err.statusCode || 500)
        .json({ status: "fail", message: err.message });
    }
  }
);

export default postRouter;
