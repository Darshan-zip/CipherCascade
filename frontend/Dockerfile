FROM node:22.13.1-alpine
WORKDIR /app
COPY package.json ./
RUN npm ci --no-audit --no-fund
COPY . .
CMD ["npm","run","dev"]
