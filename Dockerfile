# Build stage
FROM node:18-slim AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy app source
COPY . .

# Runtime stage
FROM node:18-slim

WORKDIR /app

# Copy built application from builder stage
COPY --from=builder /app .

# Expose port
EXPOSE 3000

CMD ["npm", "start"]
