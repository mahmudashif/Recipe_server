# Recipe App API Documentation

## Base URL
```
http://localhost:5000/api
```

## Authentication
The API uses JWT (JSON Web Token) for authentication. Protected endpoints require a valid JWT token in the Authorization header:
```
Authorization: Bearer <your_token>
```

## Endpoints

### User Authentication

#### Register User
Creates a new user account.

```
POST /register
```

**Request Body:**
```json
{
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "1234567890",
    "password": "password123"
}
```

**Success Response (201):**
```json
{
    "message": "User registered successfully",
    "token": "<jwt_token>",
    "user": {
        "id": "<user_id>",
        "name": "John Doe",
        "email": "john@example.com",
        "phone": "1234567890"
    }
}
```

**Error Responses:**
- `400`: User already exists
- `500`: Server error

---

#### Login User
Authenticates a user and returns a JWT token.

```
POST /login
```

**Request Body:**
```json
{
    "email": "john@example.com",
    "password": "password123"
}
```

**Success Response (200):**
```json
{
    "message": "Login successful",
    "token": "<jwt_token>",
    "user": {
        "id": "<user_id>",
        "name": "John Doe",
        "email": "john@example.com",
        "phone": "1234567890"
    }
}
```

**Error Responses:**
- `404`: User not found
- `400`: Invalid password
- `500`: Server error

---

### Cart Management

#### Add Meal to Cart
Adds a meal to the user's cart. Requires authentication.

```
POST /cart/add
```

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
    "mealId": "52772"
}
```

**Success Response (200):**
```json
{
    "message": "Meal added to cart successfully",
    "cart": [
        {
            "mealId": "52772",
            "dateAdded": "2024-12-30T12:00:00.000Z"
        }
    ]
}
```

**Error Responses:**
- `400`: Meal already in cart
- `401`: No token provided
- `403`: Invalid token
- `404`: User not found
- `500`: Server error

---

#### Get Cart Contents
Retrieves the user's cart contents. Requires authentication.

```
GET /cart
```

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Success Response (200):**
```json
{
    "cart": [
        {
            "mealId": "52772",
            "dateAdded": "2024-12-30T12:00:00.000Z"
        }
    ]
}
```

**Error Responses:**
- `401`: No token provided
- `403`: Invalid token
- `404`: User not found
- `500`: Server error

---

#### Remove Meal from Cart
Removes a meal from the user's cart. Requires authentication.

```
DELETE /cart/remove/:mealId
```

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**URL Parameters:**
- `mealId`: ID of the meal to remove

**Success Response (200):**
```json
{
    "message": "Meal removed from cart successfully",
    "cart": [
        // Updated cart contents
    ]
}
```

**Error Responses:**
- `401`: No token provided
- `403`: Invalid token
- `404`: User not found
- `500`: Server error

## Error Response Format
All error responses follow this format:
```json
{
    "message": "Error description",
    "error": "Det