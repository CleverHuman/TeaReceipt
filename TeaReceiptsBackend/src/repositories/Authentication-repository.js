import { PrismaClient } from "@prisma/client";
import { generateAccessToken, generateRefreshToken, generateTokenFromRefresh } from "../Utils/GenerateJWTToken.js";
import bcrypt from "bcrypt";
const prisma = new PrismaClient();
import errorHandler from "../Utils/Errors.js";
class authRepo {
  async createUser(data, generateUserName, hashPassword) {
    try {
      const existingUser = await prisma.users.findFirst({
        where: {
          email: data.email,
        },
      });
      if (existingUser) {
        const error = errorHandler("User already exists", 404);
        throw error;
      }
      await prisma.users.create({
        data: {
          name: data.name,
          email: data.email,
          username: generateUserName(),
          password: hashPassword(data.password),
        },
      });
      return {
        success: true,
        message: "User created successfully",
        statusCode: 201,
      };
    } catch (err) {
      console.log(err);
      return err;
    }
  }
  async signin(data) {
    try {
      const userExists = await prisma.users.findFirst({
        where: {
          email: data.email,
        },
      });
      if (!userExists) {
        const error = errorHandler("User Does not exist", 404);
        throw error;
      }
      const passwordMatch = bcrypt.compareSync(
        data.password,
        userExists.password
      );
      if (!passwordMatch) {
        const error = errorHandler("Invalid username or password", 404);
        throw error;
      }
      const user = {
        id: userExists.id,
        name: userExists.name,
        email: userExists.email,
        username: userExists.username,
      };
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      return {
        statusCode: 200,
        message: "User authenticated successfully",
        accessToken,
        refreshToken
      };
    } catch (error) {
      return error;
    }
  }

  async refreshToken(token) {
    try {
      const accessToken = generateTokenFromRefresh(token);
      return {
        statusCode: 200,
        message: "User authenticated successfully",
        accessToken
      };
    } catch (error) {
      return error;
    }
  }

  async resetPassword(data) {
    try {
      const userExists = await prisma.users.findFirst({
        where: {
          email: data.email,
        },
      });
      if (data.email === "" || data.password === "") {
        const error = errorHandler("Invalid data", 404);
        throw error;
      }
      if (!userExists) {
        const error = errorHandler("User Does not exist", 404);
        throw error;
      }
      const newPassword = bcrypt.hashSync(data.password, 10);
      await prisma.users.update({
        where: {
          id: userExists.id,
        },
        data: {
          password: newPassword,
        },
      });
      return {
        success: true,
        message: "Password reset successfully",
        statusCode: 201,
      };
    } catch (error) {
      return error;
    }
  }
}

export default authRepo;
