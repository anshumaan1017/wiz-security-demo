# Minimal vulnerable Dockerfile for Wiz CLI SARIF troubleshooting

# python:3.9-alpine is small but has guaranteed known CVEs in old Python + alpine
#FROM python:3.12-alpine

#CMD ["python", "-c", "print('wiz-vuln-demo minimal')"]
# FROM registry.os.wiz.io/python:3.10

# Install additional packages
# RUN --mount=type=secret,id=WIZ_CLIENT_ID \
#     --mount=type=secret,id=WIZ_CLIENT_SECRET \
#     export $(WIZOS_SECRET_PATH=/run/secrets apk-auth) && \
#     apk add --no-cache uv

#WORKDIR /app
#COPY ./src/ /app

# Install Python dependencies
#RUN pip install -r requirements.txt

# Run the application
# CMD ["python3", "-c", "print('wiz-vuln-demo minimal')"]

# Customer's Dockerfile — node:18-bullseye for Wiz vs Prisma comparison
FROM node:18-bullseye
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "app.js"]
