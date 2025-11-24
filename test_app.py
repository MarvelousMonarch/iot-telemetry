import unittest
import json
from app import app


class TestFlaskAPI(unittest.TestCase):
    """Test cases for Flask API endpoints"""

    def setUp(self):
        """Set up test client"""
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_index(self):
        """Test GET / - Welcome endpoint"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertIn("endpoints", data["data"])
        self.assertIn("message", data["data"])

    def test_ping(self):
        """Test GET /ping - Ping endpoint"""
        response = self.client.get("/ping")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), "pong")
        self.assertIn("text/plain", response.content_type)

    def test_healthz(self):
        """Test GET /healthz - Health check endpoint"""
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["status"], "healthy")
        self.assertIn("version", data["data"])
        self.assertIn("environment", data["data"])
        self.assertIn("timestamp", data["data"])

    def test_info(self):
        """Test GET /info - Application info endpoint"""
        response = self.client.get("/info")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertIn("application", data["data"])
        self.assertIn("system", data["data"])
        self.assertIn("environment", data["data"])

    def test_version(self):
        """Test GET /version - Version endpoint"""
        response = self.client.get("/version")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertIn("version", data["data"])
        self.assertEqual(data["data"]["name"], "telemetry-service")

    def test_echo_post(self):
        """Test POST /echo - Echo endpoint"""
        test_data = {"message": "hello", "number": 42}
        response = self.client.post(
            "/echo", data=json.dumps(test_data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["echo"], test_data)
        self.assertEqual(data["data"]["method"], "POST")

    def test_echo_invalid_json(self):
        """Test POST /echo with invalid JSON"""
        response = self.client.post(
            "/echo", data="invalid json", content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertTrue(data["error"])
        self.assertEqual(data["message"], "Invalid JSON")

    def test_404(self):
        """Test 404 error handler"""
        response = self.client.get("/nonexistent")
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.data)
        self.assertTrue(data["error"])
        self.assertEqual(data["statusCode"], 404)

    def test_security_headers(self):
        """Test security headers are set"""
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertIn("Content-Security-Policy", response.headers)


if __name__ == "__main__":
    unittest.main()
