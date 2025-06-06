# 📚 Tarpaulin Management Tool

A Flask-based RESTful API for managing users, courses, and course enrollment, with integrated authentication using Auth0 and cloud data storage via Google Cloud Datastore and Cloud Storage.

---

## 🚀 Features

* 🔐 **JWT-based Authentication** using Auth0
* 👥 **User Role Management** (admin, instructor, student)
* 📦 **Google Cloud Datastore** for structured data (users, courses)
* 🖼️ **Avatar Upload & Retrieval** via Google Cloud Storage
* 📘 **Course Management** (create, edit, enroll, delete)
* ✅ **RBAC (Role-Based Access Control)** enforced on endpoints

---

## 📁 API Endpoints Overview

### 🔐 Authentication

* `POST /users/login`
  → Authenticates a user via Auth0 and returns a JWT.

* `GET /decode`
  → Verifies and decodes the JWT from the `Authorization` header.

---

### 👤 User Management

* `GET /users`
  → Get a list of all users (admin-only).

* `GET /users/<id>`
  → Retrieve user details, including associated courses and avatar.

* `POST|GET|DELETE /users/<id>/avatar`
  → Upload, retrieve, or delete a user's avatar (must be the owner).

---

### 📚 Course Management

* `POST /courses`
  → Create a new course (admin-only).

* `GET /courses`
  → List courses with pagination (`limit`, `offset`).

* `GET /courses/<id>`
  → Retrieve a specific course.

* `PATCH /courses/<id>`
  → Edit course info (admin-only).

* `DELETE /courses/<id>`
  → Delete a course (admin-only).

---

### 🎓 Enrollment Management

* `GET|PATCH /courses/<id>/students`
  → Get or modify enrolled students (admin or course instructor).

---

## ⚙️ Environment Configuration

You'll need to configure the following environment variables:

```python
CLIENT_ID = 'your-auth0-client-id'
CLIENT_SECRET = 'your-auth0-client-secret'
DOMAIN = 'your-auth0-domain'
PHOTO_BUCKET = 'your-google-cloud-storage-bucket-name'
```

Make sure to also set `app.secret_key` securely.

---

## ☁️ Cloud Setup

### Google Cloud:

* Enable **Cloud Datastore** and **Cloud Storage**.
* Create a bucket and assign the `PHOTO_BUCKET` variable to its name.
* Ensure proper IAM permissions for Datastore and Storage access.

### Auth0:

* Create an application in Auth0.
* Enable the **Resource Owner Password Flow**.
* Use `RS256` algorithm for token signing.
* Whitelist your `audience` and callback URLs.

---

## 🧪 Running Locally

```bash
# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

Access it at:
`http://127.0.0.1:8080`

---

## 🧰 Tech Stack

* **Flask**: Python web framework
* **Authlib** + **Auth0**: Authentication
* **Google Cloud**: Datastore + Storage
* **Requests**, **Jose**, **Authlib**, **six**: Supporting libraries

---

## 🛡️ Security

* All protected routes require a valid JWT in the `Authorization` header.
* Only authenticated users can view or update their own data.
* Admins have access to all user and course data.
* Input validation and filtering enforced on key endpoints.