Quick example workflow to run your Stripe demo locally
# create project (if not created)
npm init -y
npm install express stripe dotenv cors

# create .env with your Stripe keys (test keys from dashboard)
# start server
node server.js
# or for dev:
npm install --save-dev nodemon
npm run dev