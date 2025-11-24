# telemetry [![Build Status](http://192.168.100.6:5000/api/badges/dxas90/iot-telemetry/status.svg)](http://192.168.100.6:5000/dxas90/iot-telemetry)

A simple Flask microservice for learning Kubernetes, Docker, and modern Python development practices.

## 🚀 Features

- **RESTful API** with multiple endpoints
- **Health checks** and monitoring endpoints
- **CORS support** for cross-origin requests
- **Security headers** (X-Frame-Options, CSP, etc.)
- **Docker support** with multi-stage builds
- **Kubernetes ready** with deployment configurations
- **CI/CD pipelines** (GitLab CI, GitHub Actions)
- **Comprehensive testing** with pytest
- **Production-ready** with Gunicorn

## 📋 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Welcome page with API documentation |
| `/ping` | GET | Simple ping-pong health check |
| `/healthz` | GET | Detailed health check with system metrics |
| `/info` | GET | Application and system information |
| `/version` | GET | Application version information |
| `/echo` | POST | Echo back the request body |

## 🛠️ Quick Start

### Prerequisites

- Python 3.12 or higher
- Docker (optional)
- make (optional, for using Makefile commands)

### Local Development

1. **Clone the repository**
```sh
git clone https://github.com/dxas90/chart.git
cd chart
```

2. **Install dependencies**
```sh
make install
# or manually:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

3. **Run the application**
```sh
make dev
# or manually:
source .venv/bin/activate
FLASK_ENV=development flask run --host=0.0.0.0 --port=8000
```

4. **Test the API**
```sh
curl http://localhost:8000/
curl http://localhost:8000/ping
curl http://localhost:8000/healthz
```

### Running Tests

```sh
make test
# or with coverage:
make test-coverage
```

### Docker Deployment

```sh
# Build the image
make docker-build

# Run the container
make docker-run

# Or manually:
docker build -t chart .
docker run -p 8000:8000 chart
```

### OpenShift Deployment

```sh
oc new-app https://github.com/dxas90/chart.git
```

### Kubernetes Deployment

```sh
make k8s-deploy
# or manually:
kubectl apply -f k8s/
```

```text
          Git Actions:                CI System Actions:

   +-------------------------+       +-----------------+
+-►| Create a Feature Branch |   +--►| Build Container |
|  +------------+------------+   |   +--------+--------+
|               |                |            |
|               |                |            |
|      +--------▼--------+       |    +-------▼--------+
|  +--►+ Push the Branch +-------+    | Push Container |
|  |   +--------+--------+            +-------+--------+
|  |            |                             |
|  |            |                             |
|  |     +------▼------+            +---------▼-----------+
|  +-----+ Test/Verify +◄-------+   | Deploy Container to |
|        +------+------+        |   | Ephemeral Namespace |
|               |               |   +---------+-----------+
|               |               |             |
|               |               +-------------+
|               |
|               |                    +-----------------+
|               |             +-----►| Build Container |
|      +--------▼--------+    |      +--------+--------+
|  +--►+ Merge to Master +----+               |
|  |   +--------+--------+                    |
|  |            |                     +-------▼--------+
|  |            |                     | Push Container |
|  |     +------▼------+              +-------+--------+
|  +-----+ Test/Verify +◄------+              |
|        +------+------+       |              |
|               |              |    +---------▼-----------+
|               |              |    | Deploy Container to |
|               |              |    | Staging   Namespace |
|               |              |    +---------+-----------+
|               |              |              |
|               |              +--------------+
|               |
|        +------▼-----+             +---------------------+
+--------+ Tag Master +------------►| Deploy Container to |
         +------------+             |     Production      |
                                    +---------------------+
```
