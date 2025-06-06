from flask import Flask, request, jsonify, url_for, send_file
from google.cloud import datastore, storage

import requests
import io
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users"
COURSES = "courses"
PHOTO_BUCKET = ''

# Update the values of the following 3 variables
CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = ''

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users/login to use this API"


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if "username" not in content or "password" not in content:
        return {"Error": "The request body is invalid"}, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if 'error' in r.json():
        return {"Error":  "Unauthorized"}, 401
    reformated = r.json()["id_token"]

    return {"token":reformated}, 200, {'Content-Type': 'application/json'}


@app.route('/' + USERS + '/<int:id>/avatar', methods=['GET', 'POST', 'DELETE'])
def user_avatar(id):
    if request.method == 'POST':
        if 'file' not in request.files:
            return {"Error": "The request body is invalid"}, 400

        try:
            payload = verify_jwt(request)
        except Exception as e:
            print(e)
            return {"Error": "Unauthorized"}, 401

        client_sub = payload['sub']
        client_key = client.key(USERS, id)
        user_result = client.get(client_key)
        if client_sub != user_result['sub']:
            return {"Error": "You don't have permission on this resource"}, 403

        file_obj = request.files['file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(str(id))
        file_obj.seek(0)
        blob.upload_from_file(file_obj, content_type='image/png')

        avatar_url = request.url
        user_result["avatar_url"] = avatar_url
        client.put(user_result)
        return {"avatar_url": avatar_url}, 200
    elif request.method == 'GET':
        try:
            payload = verify_jwt(request)
        except:
            return {"Error": "Unauthorized"}, 401

        client_sub = payload['sub']
        client_key = client.key(USERS, id)
        user_result = client.get(client_key)
        if client_sub != user_result['sub']:
            return {"Error": "You don't have permission on this resource"}, 403

        storage_client = storage.Client()
        bucket = storage_client.bucket(PHOTO_BUCKET)
        blob = bucket.blob(str(id))

        if not blob.exists():
            return {"Error": "Not found"}, 404

        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)
        return send_file(file_obj, mimetype='image/png', download_name=str(id))
    elif request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
        except:
            return {"Error": "Unauthorized"}, 401
        client_sub = payload['sub']
        client_key = client.key(USERS, id)
        user_result = client.get(client_key)
        if client_sub != user_result['sub']:
            return {"Error": "You don't have permission on this resource"}, 403

        storage_client = storage.Client()
        bucket = storage_client.bucket(PHOTO_BUCKET)
        blob = bucket.blob(str(id))

        if not blob.exists():
            return {"Error": "Not found"}, 404
        else:
            blob.delete()
            user_result.pop("avatar_url")
            client.put(user_result)
            return '', 204


@app.route('/' + USERS, methods=["GET"])
def get_users():
    query = client.query(kind=USERS)
    try:
        payload = verify_jwt(request)
        client_sub = payload['sub']
        query.add_filter("sub", "=", client_sub)
        results = (list(query.fetch()))
        user = results[0]
        if user['role'] != 'admin':
            return {"Error": "You don't have permission on this resource"}, 403
    except:
        return {"Error":  "Unauthorized"}, 401

    user_query = client.query(kind=USERS)
    user_results = list(user_query.fetch())
    final_results = []
    for r in user_results:
        final_results.append(
            {
                "id": r.key.id,
                "sub": r.get("sub"),
                "role": r.get("role")
            }
        )

    return final_results


@app.route('/' + USERS + '/<int:id>', methods=["GET"])
def get_user(id):
    try:
        payload = verify_jwt(request)
    except:
        return {"Error": "Unauthorized"}, 401

    query = client.query(kind=USERS)
    client_sub = payload['sub']
    query.add_filter("sub", "=", client_sub)
    client_profile = (list(query.fetch()))[0]

    client_key = client.key(USERS, id)
    user_result = client.get(client_key)

    if not user_result or (client_profile["role"] != "admin" and client_profile.key.id != id):
        return {"Error": "You don't have permission on this resource"}, 403


    user_role = user_result["role"]
    final_results = {
        "id": user_result.key.id,
        "role": user_role,
        "sub": user_result.get("sub")
    }
    if user_role != "admin":
        course_list = []
        if user_role == "student":
            course_query = client.query(kind=COURSES)
            course_query.add_filter("students", "=", user_result.key.id)
            results = list(course_query.fetch())

            for result in results:
                course_list.append(
                    url_for('get_course', id=result.key.id, _external=True)
                )

        elif user_role == "instructor":
            course_query = client.query(kind=COURSES)
            course_query.add_filter("instructor_id", "=", user_result.key.id)
            results = list(course_query.fetch())

            for result in results:
                course_list.append(
                    url_for('get_course', id=result.key.id, _external=True)
                )

        final_results["courses"] = course_list

    if "avatar_url" in user_result:
        final_results["avatar_url"] = user_result.get("avatar_url")

    return final_results


def verify_fields(content):
    FIELDS = ["subject", "number", "title", "term", "instructor_id"]
    missing_fields = [field for field in FIELDS if field not in content]
    if missing_fields:
        return False
    else:
        return True


@app.route('/' + COURSES, methods=['POST'])
def courses_post():
    if request.method == 'POST':
        content = request.get_json()
        try:
            payload = verify_jwt(request)
        except:
            return {"Error": "Unauthorized"}, 401

        query = client.query(kind=USERS)
        client_sub = payload['sub']
        query.add_filter("sub", "=", client_sub)
        client_profile = (list(query.fetch()))[0]

        if client_profile and client_profile["role"] != "admin":
            return {"Error": "You don't have permission on this resource"}, 403

        valid_content = verify_fields(content)
        instructor_key = client.key(USERS, int(content["instructor_id"]))
        user_result = client.get(instructor_key)

        if not valid_content or user_result["role"] != "instructor":
            return {"Error": "The request body is invalid"}, 400

        new_course = datastore.entity.Entity(key=client.key(COURSES))
        new_course.update({
            "instructor_id": int(content["instructor_id"]),
            "number": int(content["number"]),
            "subject": content["subject"],
            "term": content["term"],
            "title": content["title"],
            "students": []
        })
        client.put(new_course)
        new_course["id"] = new_course.key.id
        self_url = url_for('get_course', id=new_course['id'], _external=True)
        new_course['self'] = self_url
        new_course.pop("students")
        return new_course, 201


@app.route('/' + COURSES + '/<int:id>', methods=["GET"])
def get_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return {"Error": "Not found"}, 404
    else:
        course['id'] = course.key.id
        self_url = url_for('get_course', id=course['id'], _external=True)
        course['self'] = self_url
        course.pop('students')
        return course, 200


@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    offset = request.args.get('offset', default=0, type=int)
    limit = request.args.get('limit', default=3, type=int)
    query = client.query(kind=COURSES)
    query.order = ['subject']

    all_courses = list(query.fetch())
    paginated_courses = all_courses[offset:offset + limit]

    courses = []
    for course in paginated_courses:
        course['id'] = course.key.id
        course['self'] = url_for('get_course', id=course['id'], _external=True)
        course.pop('students')
        courses.append(course)

    response = {
        "courses": courses
    }

    if len(paginated_courses) == limit:
        next_offset = offset + limit
        next_url = url_for('get_courses', offset=next_offset, limit=limit, _external=True)
        response['next'] = next_url

    return response, 200


@app.route('/' + COURSES + '/<int:id>', methods=["PATCH"])
def patch_course(id):
    content = request.get_json()
    try:
        payload = verify_jwt(request)
    except:
        return {"Error": "Unauthorized"}, 401

    query = client.query(kind=USERS)
    client_sub = payload['sub']
    query.add_filter("sub", "=", client_sub)
    client_profile = (list(query.fetch()))[0]

    course_key = client.key(COURSES, id)
    course_result = client.get(course_key)

    if not course_result or (client_profile["role"] != "admin"):
        return {"Error": "You don't have permission on this resource"}, 403


    valid_instructor = True
    if content.get("instructor_id"):
        instructor_key = client.key(USERS, content["instructor_id"])
        instructor_result = client.get(instructor_key)
        if not instructor_result or instructor_result["role"] != "instructor":
            valid_instructor = False

    patchable_fields = ["subject", "number", "title", "term", "instructor_id"]

    if valid_instructor:
        for field in patchable_fields:
            if field in content:
                course_result[field] = content[field]
        client.put(course_result)
        course_result["id"] = course_result.key.id
        course_result['self'] = url_for('get_course', id=course_result['id'], _external=True)
        course_result.pop('students')
        return course_result, 200
    else:
        return {"Error": "The request body is invalid"}, 400


@app.route('/' + COURSES + '/<int:id>', methods=["DELETE"])
def delete_course(id):
    try:
        payload = verify_jwt(request)
    except:
        return {"Error": "Unauthorized"}, 401

    query = client.query(kind=USERS)
    client_sub = payload['sub']
    query.add_filter("sub", "=", client_sub)
    client_profile = (list(query.fetch()))[0]

    course_key = client.key(COURSES, id)
    course_result = client.get(course_key)

    if not course_result or (client_profile["role"] != "admin"):
        return {"Error": "You don't have permission on this resource"}, 403

    client.delete(course_key)
    return '', 204


@app.route('/' + COURSES + '/<int:id>/students', methods=["GET", "PATCH"])
def patch_enrollment(id):
    try:
        payload = verify_jwt(request)
    except:
        return {"Error": "Unauthorized"}, 401

    content = request.get_json()

    query = client.query(kind=USERS)
    client_sub = payload['sub']
    query.add_filter("sub", "=", client_sub)
    client_profile = (list(query.fetch()))[0]

    course_key = client.key(COURSES, id)
    course_result = client.get(course_key)

    if not course_result or (client_profile["role"] != "admin" and client_profile.key.id != course_result["instructor_id"]):
        return {"Error": "You don't have permission on this resource"}, 403

    if request.method == "PATCH":
        add_list = list(set(content.get("add", [])))
        remove_list = list(set(content.get("remove", [])))
        no_common = True
        valid_users = True

        combined_list = add_list + remove_list
        encountered = set()

        for user_id in combined_list:
            user_key = client.key(USERS, user_id)
            user_result = client.get(user_key)
            if not user_result or user_result["role"] != "student":
                valid_users = False

            if user_id in encountered:
                no_common = False
            else:
                encountered.add(user_id)

        if not no_common or not valid_users:
            return {"Error": "Enrollment data is invalid"}, 409

        enrolled_students = course_result["students"]
        for s_id in add_list:
            if s_id not in enrolled_students:
                enrolled_students.append(s_id)

        for s_id in remove_list:
            if s_id in enrolled_students:
                enrolled_students.remove(s_id)

        course_result["students"] = enrolled_students
        client.put(course_result)
        return '', 200

    elif request.method == "GET":
        return course_result["students"], 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

