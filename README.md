# ProperAuth

ProperAuth is an advanced authentication backend that implements access tokens, refresh tokens, session tracking, and logout support using Express and MongoDB.

## Features
- Register and login users with duplicate username/email checks.
- Password hashing using Node.js crypto.
- Short-lived JWT access tokens and long-lived refresh tokens.
- Refresh token stored in secure HTTP-only cookies.
- Session collection storing refresh token hash, IP address, user agent, timestamps, and revoked status.
- Refresh-token rotation for improved session security.
- Logout flow that revokes active sessions.
- Current-user endpoint for fetching authenticated user details.

## Tech Stack
Node.js, Express.js, MongoDB, Mongoose, JWT, Cookie Parser, Morgan, Dotenv

## How to Run

1. Install dependencies:
   npm install
2. Create a .env file:
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
3. Start development server:
   npm run dev
