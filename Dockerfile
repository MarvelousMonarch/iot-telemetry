# syntax=docker/dockerfile:1

# Comments are provided throughout this file to help you get started.
# If you need more help, visit the Dockerfile reference guide at
# https://docs.docker.com/engine/reference/builder/

ARG PYTHON_VERSION=3.12

# Base stage with common dependencies
FROM python:${PYTHON_VERSION}-slim AS base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    default-libmysqlclient-dev \
    gettext-base && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Development stage
FROM base AS development

# Download dependencies as a separate step to take advantage of Docker's caching.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=requirements.txt \
    --mount=type=bind,source=requirements-dev.txt,target=requirements-dev.txt \
    python -m pip install -r requirements.txt -r requirements-dev.txt

# Copy the source code into the container.
COPY . .

# Expose the port that the application listens on.
EXPOSE 8000

# Run the application in development mode
CMD ["python", "app.py"]

# Production stage
FROM base AS production

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user
ARG UID=1000
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

# Ensure standard temporary directories exist and are writable by the app.
# Keeping them writable by all (sticky bit) makes them usable when the container
# runs with readOnlyRootFilesystem; at runtime the chart mounts an emptyDir to /tmp.
RUN mkdir -p /tmp /var/tmp /usr/tmp && chmod 1777 /tmp /var/tmp /usr/tmp

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=requirements.txt \
    python -m pip install -r requirements.txt

# Switch to the non-privileged user to run the application.
USER appuser

# Copy the source code into the container.
# Copy the app into the container image. This is done as root during build time
# (even if the build switches USER earlier). Files are left owned by root, but
# the mounted /tmp will be available at runtime for write operations.
COPY . .

# Ensure Python and other libraries use the expected TMPDIR
ENV TMPDIR=/tmp

# Expose the port that the application listens on.
EXPOSE 8000

# Run the application.
CMD ["gunicorn", "app:app", "-c", "gunicorn_config.py"]
