# MasterofJokes

A Flask web application where users share and discover jokes through a credit-based economy. Inspired by the "take a penny, leave a penny" concept -- post a joke to earn a credit, spend a credit to read someone else's joke.

## How It Works

1. **Register** with a nickname, email, and password
2. **Post a joke** to earn 1 credit (new users start with a balance of 0; a database trigger auto-increments balance on each new joke)
3. **Browse jokes** from other users -- reading a new joke costs 1 credit
4. **Rate jokes** on a 1-10 scale (one rating per user per joke)
5. **Manage your jokes** -- edit the body or delete jokes you've posted

Users can only view jokes they can afford. Once a joke is viewed, re-reading it is free (tracked via the `jokesViewed` table).

## Tech Stack

| Layer       | Technology                                        |
|-------------|---------------------------------------------------|
| Backend     | Python 3.11 / Flask with Blueprints               |
| Database    | SQLite (file-based, lives in `instance/`)         |
| Templating  | Jinja2 (server-side rendering)                    |
| Auth        | Session-based with Werkzeug scrypt password hashing |
| Deployment  | Docker + Waitress WSGI server                     |
| Build       | Flit (`pyproject.toml`)                           |

## Project Structure

```
MasterofJokes/
├── flaskr/                     # Application package
│   ├── __init__.py             # App factory, logging config
│   ├── auth.py                 # Auth blueprint: register, login, logout
│   ├── joke.py                 # Jokes blueprint: CRUD, ratings, moderator tools
│   ├── db.py                   # Database init, CLI commands
│   ├── error_register.py       # Custom 404/500 error handlers
│   ├── schema.sql              # Database schema + seed data
│   ├── static/
│   │   └── style.css           # Application styles
│   └── templates/
│       ├── base.html           # Shared layout (nav, flash messages, footer)
│       ├── auth/
│       │   ├── login.html
│       │   └── register.html
│       └── jokes/
│           ├── create.html     # New joke form
│           ├── takeAJoke.html  # Browse available jokes
│           ├── myjokes.html    # User's own jokes
│           ├── viewSingle.html # Single joke view + rating form
│           ├── update.html     # Edit/delete a joke
│           ├── moderator.html  # Admin dashboard
│           └── index.html      # Legacy posts view
├── tests/                      # Pytest test suite
│   ├── conftest.py             # Fixtures (app, client, auth helper)
│   ├── data.sql                # Test seed data
│   ├── test_auth.py
│   ├── test_blog.py
│   ├── test_db.py
│   └── test_factory.py
├── instance/
│   └── config.py               # Instance config (SECRET_KEY override)
├── Dockerfile
├── pyproject.toml              # Build config (flit)
└── .gitignore
```

## Database Schema

**Tables:**

- **`user`** -- id, nickname (unique), email, hashed password, jokebalance, userRole (0=user, 1=moderator)
- **`jokes`** -- id, author_id (FK), title, body, created timestamp, ratings sum, numberOfRatings
- **`jokesViewed`** -- tracks which user viewed/rated which joke (prevents double-charging and double-rating)

**Trigger:** `incrementJokeBalance` fires after each joke insert to auto-increment the author's balance and mark the joke as "viewed" by its author.

## Roles

| Role         | userRole | Capabilities |
|--------------|----------|--------------|
| Regular User | 0        | Post, browse, rate, edit, and delete own jokes |
| Moderator    | 1        | User management (create, delete, promote/demote), balance adjustment, joke management, toggle logging level (INFO/DEBUG) |

## Getting Started

### Prerequisites

- Python 3.9+ (3.11 recommended)
- pip

### Local Development

```bash
# Clone the repository
git clone https://github.com/sathya-hardy/MasterofJokes.git
cd MasterofJokes

# Install in development mode
pip install -e .

# Initialize the database (creates tables + seeds a default moderator)
flask --app flaskr init-db

# (Optional) Create an additional moderator account via CLI
flask --app flaskr create-moderator

# Run the development server
flask --app flaskr run --debug
```

The app will be available at `http://localhost:5000`.

### Default Moderator Account

The database schema seeds a moderator on init:

| Field    | Value              |
|----------|--------------------|
| Nickname | `moderator1`       |
| Email    | `mod@gmail.com`    |
| Password | `ilovemoderation`  |

### Docker

```bash
# Build the wheel first
pip install flit
flit build

# Build and run
docker build -t masterofjokes .
docker run -p 8080:8080 masterofjokes
```

The app will be available at `http://localhost:8080`.

## Running Tests

```bash
pip install pytest
pytest tests/
```

## Environment Variables

| Variable    | Default | Description |
|-------------|---------|-------------|
| `LOG_LEVEL` | `INFO`  | Initial logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `SECRET_KEY`| `dev`   | Flask session secret; override in `instance/config.py` for production |

## Logging

Logs are written to both the console and `moj.log`. The logging level can be changed at runtime by a moderator through the dashboard (toggles between INFO and DEBUG). The `set_log_level()` function in `__init__.py` updates the root logger so all modules are affected.

## API / Routes

### Authentication (`/auth`)

| Method | Route           | Description            |
|--------|-----------------|------------------------|
| GET/POST | `/auth/register` | Create a new account |
| GET/POST | `/auth/login`    | Log in (nickname or email) |
| GET    | `/auth/logout`   | Log out and clear session |

### Jokes (`/`)

| Method | Route                  | Description                          |
|--------|------------------------|--------------------------------------|
| GET    | `/`                    | Browse jokes (or moderator dashboard) |
| GET    | `/myjokes`             | List your own jokes                  |
| GET/POST | `/create`            | Post a new joke                      |
| GET    | `/viewSingle/<id>`     | View a single joke                   |
| POST   | `/viewSingle/<id>`     | Rate a joke (1-10)                   |
| GET/POST | `/<id>/update`       | Edit a joke's body                   |
| GET/POST | `/<id>/delete`       | Delete a joke                        |

### Moderator

| Method | Route                              | Description                    |
|--------|------------------------------------|--------------------------------|
| GET    | `/moderator`                       | Dashboard overview             |
| POST   | `/moderator`                       | Promote/demote users           |
| POST   | `/moderator.update_balance`        | Adjust a user's joke balance   |
| POST   | `/moderator.initializeUser`        | Create a new user account      |
| POST   | `/moderator.updateLoggingLevel`    | Toggle INFO/DEBUG logging      |

## License

This project was built as a learning exercise using the [Flask tutorial](https://flask.palletsprojects.com/en/stable/tutorial/) as a starting point.
