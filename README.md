# Haris Yoonus & Co — Secure Client Portal

A secure document management and client portal for **HY & Co**, a Chartered Accountant firm.

## Features

- **Encrypted Document Storage** — Files are AES-256 encrypted and stored on Cloudflare R2
- **Client Dashboard** — Clients can view/download their documents and manage passwords
- **Admin Panel** — Full client management, document uploads, credential vault, Power BI integration
- **Disaster Recovery** — Encrypted metadata backups in R2 enable full DB rebuild
- **Route Protection** — Server-side JWT guards on all protected pages
- **Impersonation** — Admins can view the portal as any client

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla HTML/CSS/JS |
| Backend | Node.js + Express |
| Database | Neon PostgreSQL |
| File Storage | Cloudflare R2 (S3-compatible) |
| Auth | JWT + bcrypt |
| Encryption | AES-256-CBC |

## Project Structure

```
├── backend/
│   ├── server.js        # Express API server
│   ├── db.js            # Neon PostgreSQL connection
│   ├── package.json
│   └── .env.example     # Required environment variables
├── frontend/
│   ├── index.html       # Landing page
│   ├── login.html       # Login page
│   ├── admin.html       # Admin SPA
│   ├── dashboard.html   # Client dashboard
│   ├── about.html       # About page
│   ├── contact.html     # Contact page
│   ├── services.html    # Services page
│   ├── style.css        # Global styles
│   └── main.js          # Frontend utilities
└── .gitignore
```

## Setup

1. **Clone the repo**
   ```bash
   git clone <repo-url>
   cd AntiGravity
   ```

2. **Install dependencies**
   ```bash
   cd backend
   npm install
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Fill in your real values
   ```

4. **Run locally**
   ```bash
   npm run dev
   ```
   Visit `http://localhost:3000`

## Environment Variables

See [`backend/.env.example`](backend/.env.example) for the full list. All variables are **required** — the server will not start without them.

## Default Admin

On first run, the server seeds an admin account:
- **Email:** `ca.hyandco@gmail.com`
- **Password:** `admin123`

> ⚠️ **Change this password immediately after first login.**
