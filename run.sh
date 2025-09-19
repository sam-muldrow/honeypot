docker build -t honeypot .
docker run -p 22:22 -d --rm honeypot
