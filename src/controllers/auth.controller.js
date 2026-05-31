import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";

export async function register(req, res) {
  const { username, email, password } = req.body;

  const isAlreadyRegistered = await userModel.findOne({
    $or: [
      {username}, {email}
    ]
  })

  if(isAlreadyRegistered) {
    return res.status(409).json({
      message: "Username or email already exists!!"
    })
  }

  const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

  const user = await userModel.create({
    username,
    email,
    password: hashedPassword
  })

  const refreshToken = jwt.sign({
    id: user._id
  }, config.JWT_SECRET, { expiresIn: "5d"})

  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

  const session = await sessionModel.create({
    user: user._id,
    refreshTokenHash,
    ip: req.ip,
    userAgent: req.headers[ "user-agent" ]
  })

  const accessToken = jwt.sign({
    id: user._id,
    sessionId: session._id
  }, config.JWT_SECRET, { expiresIn: "5m"})
  
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 5 * 24 * 60 * 60 * 1000
  });

  res.status(201).json({
    message: "User created!!",
    user: {
      username: user.username,
      email: user.email
    }, accessToken
  })
}

export async function login(req, res) {
  const {email, password} = req.body;

  const user = await userModel.findOne({email})

  if(!user) {
    return res.status(401).json({
      message: "Invalid email or password."
    })
  }

  const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

  const isValidPassword = hashedPassword === user.password;

  if(!isValidPassword) {
    return res.status(401).json({
      message: "Invalid email or password."
    })
  }

  const refreshToken = jwt.sign({
    id: user._id
  }, config.JWT_SECRET, { expiresIn: "5d"})

  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

  const session = await sessionModel.create({
    user: user._id,
    refreshTokenHash,
    ip: req.ip,
    userAgent: req.headers[ "user-agent" ]
  })

  const accessToken = jwt.sign({
    id: user._id,
    sessionId: session._id
  }, config.JWT_SECRET, { expiresIn: "5m"})

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 5 * 24 * 60 * 60 * 1000
  });

  res.status(201).json({
    message: "User logged in!!",
    user: {
      username: user.username,
      email: user.email
    }, accessToken
  })

}


export async function getMe(req, res) {
  const token = req.cookies.refreshToken;

  if(!token) {
    return res.status(401).json({
      message: "Token not found!!"
    })
  }
  const decoded = jwt.verify(token, config.JWT_SECRET)

  const user = await userModel.findById(decoded.id);

  res.status(200).json({
    message: "User fetched.",
    user: {
      username: user.username,
      email: user.email
    }
  });
}

export async function refreshToken(req, res) {
  const refreshToken = req.cookies.refreshToken;

  if(!refreshToken) {
    return res.status(401).json({
      message: "Refresh token not found"
    })
  }

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

  const session = await sessionModel.findOne({
    refreshTokenHash,
    revoked: false
  });

  if(!session) {
    return res.status(401).json({
      message: "Refresh token invalid"
    })
  }

  const accessToken = jwt.sign({
    id: decoded.id
  }, config.JWT_SECRET, { expiresIn: "5m"})

  const newRefreshToken = jwt.sign({
    id: decoded.id
  }, config.JWT_SECRET, { expiresIn: "5d"})

  const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

  session.refreshTokenHash = newRefreshTokenHash;
  await session.save();

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 5 * 24 * 60 * 60 * 1000
  });

  res.status(200).json({
    message: "Access token refreshed.",
    accessToken
  })
}

export async function logout(req, res) {
  const refreshToken = req.cookies.refreshToken;
  if(!refreshToken) {
    return res.status(400).json({
      message: "Refresh token not found"
    })
  }

  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

  const session = await sessionModel.findOne({
    refreshTokenHash,
    revoked: false
  })

  if(!session) {
    return res.status(400).json({
      message: "Refresh token invalid"
    })
  }

  session.revoked = true;
  await session.save();

  res.clearCookie("refreshToken");

  res.status(200).json({
    message: "Logged out!!"
  })
}