FROM python:3.12-slim

WORKDIR /app
COPY app/ app/
COPY tests/ tests/
COPY verify/ verify/

ENV PORT=8080
EXPOSE 8080

# Default command runs the review/verify web app; the Compose `verify`
# service overrides it with the one-shot test+smoke run.
CMD ["python", "-m", "app.server"]
