FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production

# Bundle app source
COPY . .

# Ensure uploads directory exists (just in case, to prevent immediate crashes)
RUN mkdir -p uploads

# Bind to the port provided by Cloud Run
ENV PORT=8080
EXPOSE 8080

CMD [ "npm", "start" ]
