# Use a multi-stage build
FROM zricethezav/gitleaks:latest AS gitleaks
FROM python:3.10-alpine3.16

# Set up Python environment - Startinng point.
WORKDIR /code

# Copy Gitleaks from the first stage
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/gitleaks

# Copy the Python script to the container
COPY src/transform_results.py /app/transform_results.py
COPY src/requirements.txt /src/requirements.txt

# Install Python dependencies
RUN apk add --no-cache bash
RUN pip install -r /src/requirements.txt

# Set entrypoint to Python
ENTRYPOINT ["python3", "/app/transform_results.py"]
