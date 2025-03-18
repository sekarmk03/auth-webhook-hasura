# Use an official Node.js runtime as a parent image
FROM node:18-alpine

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --only=production

# Copy the rest of the application
COPY . .

# Expose the correct port
EXPOSE 5000

# Start the application using the correct script
CMD ["npm", "start"]
