# Use a lightweight Node.js runtime as the base image
FROM node:20-alpine

# Install OpenSSL, which is required by server.js to generate certificates
RUN apk add --no-cache openssl

# Set the working directory inside the container
WORKDIR /app

# Copy package files first to leverage Docker's caching layer
COPY package.json ./

# Install production dependencies only
RUN npm install --production

# Copy the rest of the application files (server.js, public directory, etc.)
COPY . .

# Expose the default port used by the gateway
EXPOSE 2222

# Set default environment variables
ENV PORT=2222
ENV NODE_ENV=production

# Define the command to start the application
CMD ["npm", "start"]
