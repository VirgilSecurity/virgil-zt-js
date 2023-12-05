# syntax=docker/dockerfile:1
FROM node:18.16.0-alpine as build
RUN apk add --no-cache python3 g++ make
WORKDIR /frontend
COPY package*.json .
RUN yarn install
COPY . .
RUN yarn run build
FROM nginx:1.19
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /frontend/build /usr/share/nginx/html
