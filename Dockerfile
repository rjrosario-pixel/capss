# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (optional, only if you need build tools, e.g. for numpy/pandas)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Copy your requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your app code into the container
COPY . .

# Set environment variables (optional, you can also do this in Northflank UI)
ENV FLASK_ENV=production

# Expose the port your app will run on (Northflank assigns correct PORT env var)
EXPOSE 8080

# Run Gunicorn with eventlet worker (matches your app's entry point: main:socketio)
CMD ["gunicorn", "main:socketio", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:${PORT}"]
