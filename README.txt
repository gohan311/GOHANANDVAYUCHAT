VAYU OFFLINE CHAT SYSTEM
========================

PROJECT CONTENTS
- server.js          Express server, SQLite database, login and admin API
- package.json       Dependencies and start command
- public/index.html  Website layout
- public/style.css   Responsive hacker / Matrix styling
- public/app.js      Browser-side chat application

RUN LOCALLY
1. Install Node.js 20 or newer.
2. Open a terminal in this project folder.
3. Run: npm install
4. Set environment variables:
   SESSION_SECRET = a long random secret (at least 32 characters)
   ADMIN_USERNAME = the username you want to use for the FIRST account
   DATA_DIR = ./data
5. Run: npm start
6. Open http://localhost:3000

IMPORTANT ADMIN SETUP
- ADMIN_USERNAME only grants admin status to the first account created,
  and only if its username matches this environment variable.
- Set ADMIN_USERNAME before the first registration.
- If the database already contains accounts, changing ADMIN_USERNAME
  will not promote another account.
- Never share SESSION_SECRET or your admin login password.

RENDER DEPLOYMENT
1. Upload the CONTENTS of this folder to a GitHub repository.
2. In Render, create a Web Service connected to that repository.
3. Build command: npm install
4. Start command: npm start
5. Add a Persistent Disk mounted at /var/data.
6. Set these environment variables:
   NODE_ENV = production
   DATA_DIR = /var/data
   SESSION_SECRET = a long, random secret of at least 32 characters
   ADMIN_USERNAME = your chosen first admin username
7. Deploy, then create the first account using that exact username.

FEATURES
- Username and password registration; no email required.
- Passwords are hashed before storage.
- Group chat and private one-to-one messages.
- Online presence and join/leave notices.
- Admin rename, ban, timeout, and password reset controls.
- Responsive layout for phones, tablets, and computers.
- SQLite data persists when the Render disk is configured correctly.

LIMITATIONS / SAFETY
- The gate password shown in the browser is a decorative access gate,
  not real security. Anyone who can inspect the website can find it.
- Use HTTPS hosting and a strong SESSION_SECRET.
- Do not use this starter for sensitive or confidential conversations.
- Bans disable account access; account records and chat history remain.
- Private messages are restricted by the server API, but this is a
  starter project and should receive a security review before public use.
- Keep the Render persistent disk attached. Without it, database and
  session files may be lost when the service restarts or redeploys.
