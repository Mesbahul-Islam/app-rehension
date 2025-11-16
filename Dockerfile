# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code
COPY . .

# Create data directory for cache
RUN mkdir -p /app/data

# Make port 8080 available (Cloud Run default)
EXPOSE 8080

# Set environment variable for production
ENV PYTHONUNBUFFERED=1

# Use gunicorn for production with proper timeout settings
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 300 --access-logfile - --error-logfile - app:app
