# Build stage
FROM node:18-slim AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    apt-transport-https \
    iptables git \
    ca-certificates \
    curl 

RUN iptables -t nat -N pse \
    iptables -t nat -A OUTPUT -j pse
    PSE_IP=\$(getent hosts ${containerName} | awk '{ print \$1 }')
    echo "PSE_IP is \${PSE_IP}"
    iptables -t nat -A ${containerName} -p tcp -m tcp --dport 443 -j DNAT --to-destination \${PSE_IP}:12345

ENV caFile /etc/ssl/certs/pse.pem
RUN curl -s -o ${caFile} https://pse.invisirisk.com/ca \
                -H 'User-Agent: Jenkins' \
                --insecure

RUN update ca-certificate 

ENV NODE_EXTRA_CA_CERTS /etc/ssl/certs/pse.pem
ENV REQUESTS_CA_BUNDLE /etc/ssl/certs/pse.pem

RUN npm config set cafile ${caFile} \
    npm config set strict-ssl false
                
# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy app source
COPY . .

# Runtime stage
FROM node:18-slim

# Install Docker
RUN apt-get update && \
    apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli

WORKDIR /app

# Copy built application from builder stage
COPY --from=builder /app .

# Expose port
EXPOSE 3000

CMD ["npm", "start"]
