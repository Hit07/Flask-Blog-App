# Flask Blog Application

This is a simple blog application built with Flask, SQLAlchemy, and other modern web technologies. Users can register, log in, create posts, and comment on posts. Admin users have the ability to edit and delete posts.

## Features

- User registration and authentication
- Create, edit, and delete blog posts
- Add and display comments on blog posts
- Admin-only privileges for editing and deleting posts
- Gravatar integration for user avatars
- CKEditor integration for rich text editing

## Getting Started

These instructions will help you set up the project on your local machine for development and testing purposes.

### Prerequisites

- Python 3.8 or higher
- Flask
- SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-Bootstrap
- Flask-CKEditor

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/flask-blog.git
    cd flask-blog
    ```

2. Create a virtual environment:
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Set up the database:
    ```sh
    flask db init
    flask db migrate
    flask db upgrade
    ```

5. Run the application:
    ```sh
    flask run
    ```

### Configuration

Before running the application, make sure to configure your environment variables. Create a `.env` file in the root directory of your project with the following content:

```env
FLASK_APP=main.py
FLASK_ENV=development
SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///blog_posts.db
