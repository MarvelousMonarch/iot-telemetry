import os
import sys
import logging
from datetime import datetime, timezone
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.resources import Resource

# Configure logging
logging.basicConfig(
    level=(
        logging.DEBUG if os.environ.get("FLASK_ENV") == "development" else logging.INFO
    ),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Disable werkzeug access logging to avoid duplicates
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

# Initialize OpenTelemetry tracing
if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
    resource = Resource.create(
        {
            "service.name": "chart",
            "service.version": os.environ.get("APP_VERSION", "0.0.1"),
            "deployment.environment": os.environ.get("FLASK_ENV", "development"),
        }
    )
    trace.set_tracer_provider(TracerProvider(resource=resource))
    otlp_exporter = OTLPSpanExporter(
        endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
        insecure=True,
    )
    trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(otlp_exporter))
    logger.info("OpenTelemetry tracing enabled")
else:
    logger.info("OpenTelemetry tracing disabled (OTEL_EXPORTER_OTLP_ENDPOINT not set)")

tracer = trace.get_tracer(__name__)

app = Flask(__name__)

# Instrument Flask with OpenTelemetry
FlaskInstrumentor().instrument_app(app)

# Configure CORS
CORS(app, origins=os.environ.get("CORS_ORIGIN", "*"))

# Prometheus metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)

# Application metadata
APP_INFO = {
    "name": "telemetry-service",
    "version": os.environ.get("APP_VERSION", "0.0.1"),
    "environment": os.environ.get("FLASK_ENV", "development"),
    "timestamp": datetime.now(timezone.utc).isoformat(),
}

# In-memory telemetry storage (simple list for demo purposes)
telemetry_data = []


# Middleware for logging
@app.before_request
def log_request():
    if os.environ.get("FLASK_ENV") != "test":
        user_agent = request.headers.get("User-Agent", "Unknown")
        logger.info(f"{request.method} {request.path} - User-Agent: {user_agent}")
    request._start_time = datetime.now(timezone.utc)


# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    # Track Prometheus metrics
    if hasattr(request, "_start_time") and request.endpoint != "metrics":
        duration = (datetime.now(timezone.utc) - request._start_time).total_seconds()
        REQUEST_DURATION.labels(
            method=request.method, endpoint=request.endpoint or "unknown"
        ).observe(duration)
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.endpoint or "unknown",
            status=response.status_code,
        ).inc()

    return response


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return (
        jsonify(
            {
                "error": True,
                "message": "Resource not found",
                "statusCode": 404,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ),
        404,
    )


@app.errorhandler(500)
def internal_error(error):
    return (
        jsonify(
            {
                "error": True,
                "message": "Internal Server Error",
                "statusCode": 500,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": (
                    str(error) if os.environ.get("FLASK_ENV") != "production" else None
                ),
            }
        ),
        500,
    )


# Route: Welcome page
@app.route("/")
def index():
    """Welcome endpoint with API documentation"""
    welcome_data = {
        "message": "Welcome to Telemetry Service API",
        "description": "IoT Telemetry Ingestion Service for collecting sensor data",
        "documentation": {"swagger": None, "postman": None},
        "links": {
            "repository": "https://github.com/dxas90/iot-platform",
            "issues": "https://github.com/dxas90/iot-platform/issues",
        },
        "endpoints": [
            {
                "path": "/",
                "method": "GET",
                "description": "API welcome and documentation",
            },
            {
                "path": "/ping",
                "method": "GET",
                "description": "Simple ping-pong response",
            },
            {
                "path": "/healthz",
                "method": "GET",
                "description": "Health check endpoint",
            },
            {
                "path": "/info",
                "method": "GET",
                "description": "Application and system information",
            },
            {
                "path": "/telemetry",
                "method": "POST",
                "description": "Ingest IoT device telemetry data",
            },
            {
                "path": "/telemetry",
                "method": "GET",
                "description": "Retrieve all telemetry data",
            },
            {
                "path": "/echo",
                "method": "POST",
                "description": "Echo back the request body",
            },
            {
                "path": "/metrics",
                "method": "GET",
                "description": "Prometheus metrics endpoint",
            },
        ],
    }
    return jsonify(
        {
            "success": True,
            "data": welcome_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# Route: Ping
@app.route("/ping")
def ping():
    """Simple ping-pong response"""
    return "pong", 200, {"Content-Type": "text/plain"}


# Route: Health check
@app.route("/healthz")
def healthz():
    """Health check endpoint with basic information"""
    health_data = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": APP_INFO["version"],
        "environment": APP_INFO["environment"],
    }

    return jsonify(
        {
            "success": True,
            "data": health_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# Route: Application info
@app.route("/info")
def info():
    """Application and system information endpoint"""
    system_info = {
        "application": APP_INFO,
        "system": {
            "python_version": sys.version,
        },
        "environment": {
            "python_env": os.environ.get("PYTHON_ENV", "Not set"),
            "flask_env": os.environ.get("FLASK_ENV", "development"),
            "port": os.environ.get("PORT", "8000"),
            "host": os.environ.get("HOST", "0.0.0.0"),
        },
    }

    return jsonify(
        {
            "success": True,
            "data": system_info,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# Route: POST Telemetry Data
@app.route("/telemetry", methods=["POST"])
def ingest_telemetry():
    """Ingest telemetry data from IoT devices"""
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ["device_id", "temperature", "voltage"]
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "error": True,
                    "message": f"Missing required field: {field}",
                    "statusCode": 400,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }), 400

        # Create telemetry record
        telemetry_record = {
            "id": len(telemetry_data) + 1,
            "device_id": data["device_id"],
            "temperature": float(data["temperature"]),
            "voltage": float(data["voltage"]),
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "received_at": datetime.now(timezone.utc).isoformat(),
        }

        # Store in memory
        telemetry_data.append(telemetry_record)

        logger.info(f"Telemetry ingested: device={telemetry_record['device_id']}, temp={telemetry_record['temperature']}°C, voltage={telemetry_record['voltage']}V")

        return jsonify({
            "success": True,
            "data": telemetry_record,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 201

    except ValueError as e:
        return jsonify({
            "error": True,
            "message": f"Invalid data format: {str(e)}",
            "statusCode": 400,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 400
    except Exception as e:
        logger.error(f"Error ingesting telemetry: {str(e)}")
        return jsonify({
            "error": True,
            "message": "Internal server error",
            "statusCode": 500,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 500


# Route: GET Telemetry Data
@app.route("/telemetry", methods=["GET"])
def get_telemetry():
    """Retrieve all telemetry data"""
    # Optional query parameters for filtering
    device_id = request.args.get("device_id")
    limit = request.args.get("limit", type=int)

    filtered_data = telemetry_data

    # Filter by device_id if provided
    if device_id:
        filtered_data = [t for t in filtered_data if t["device_id"] == device_id]

    # Limit results if specified
    if limit and limit > 0:
        filtered_data = filtered_data[-limit:]

    return jsonify({
        "success": True,
        "data": {
            "telemetry": filtered_data,
            "total": len(filtered_data),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# Route: Echo (for testing POST requests)
@app.route("/echo", methods=["POST"])
def echo():
    """Echo back the request body"""
    try:
        data = request.get_json()
        return jsonify(
            {
                "success": True,
                "data": {
                    "echo": data,
                    "headers": dict(request.headers),
                    "method": request.method,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception:
        return (
            jsonify(
                {
                    "error": True,
                    "message": "Invalid JSON",
                    "statusCode": 400,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            400,
        )


# Route: Prometheus metrics
@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


# Route: Version
@app.route("/version")
def version():
    """Get application version"""
    return jsonify(
        {
            "success": True,
            "data": {
                "version": APP_INFO["version"],
                "name": APP_INFO["name"],
                "environment": APP_INFO["environment"],
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("FLASK_ENV", "development") == "development"

    logger.info(f"🚀 Server starting at http://{host}:{port}/")
    logger.info(f"📊 Environment: {APP_INFO['environment']}")
    logger.info(f"📦 Version: {APP_INFO['version']}")
    logger.info(f"🕐 Started at: {APP_INFO['timestamp']}")

    app.run(host=host, port=port, debug=debug)
