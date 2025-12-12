# Use a Python base image that is compatible with common C libraries
FROM python:3.11-slim

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install critical system dependencies for WeasyPrint (Cairo, Pango, GDK-PixBuf) and PostgreSQL
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libffi-dev \
        libpq-dev \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
        libpango1.0-0 \
        libcairo2 \
        libgdk-pixbuf2.0-0 \
        shared-mime-info && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the dependency file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Set the port and command (The Procfile overrides this)
ENV PORT 8080
CMD ["gunicorn", "app:app"]
