# Access Control System for Small Organizations

This project implements a basic access control system with user authentication, role-based access control, and user management, using Python Flask, SQLite, and SQLAlchemy.

## Features

*   User Authentication (Login, Logout)
*   Password Hashing
*   Role-Based Access Control (Admin, Regular User)
*   User Registration (Admin only)
*   User Deletion (Admin only)
*   View Users (Admin only)
*   Profile Management (Edit Profile, Change Password)
*   Profile Pictures (Upload, Validation)
*   Password Reset Functionality

## Prerequisites

*   Python 3.8 or higher
*   pip

## Installation

1.  Clone this repository:
    ```bash
    git clone https://github.com/s0y4hh/Information-Assurance-and-Security-FP.git

2.  Navigate to the project directory:

    ```bash
    cd Information-Assurance-and-Security-FP
    ```

3.  Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Database Initialization

The database (db.sqlite3) will be automatically created on the first run. An admin user with the following credentials will be added:

*   **Email:** `admin@example.com`
*   **Password:** `admin`
*   **Role:** `admin`

## Running the Application

```bash
python app.py
