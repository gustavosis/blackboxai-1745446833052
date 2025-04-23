## MyService

A modern platform for connecting service providers with users. Built with Node.js, Express, SQLite, and modern frontend technologies.

## Features

- 🔍 Search for service providers by type and location
- 📍 Geolocation-based provider search
- 📹 Video recording for provider presentations
- 👤 User authentication and registration
- 💼 Provider profiles with document uploads
- 📝 Service request management
- 📱 Responsive design with Tailwind CSS

## Project Structure

```
myservice/
├── public/               # Static frontend files
│   ├── index.html       # Main application page
│   ├── register.html    # Provider registration page
│   ├── styles.css       # Global styles
│   └── video-recording.html  # Video recording interface
│
├── server/              # Backend server code
│   ├── config.js        # Application configuration
│   ├── db.js           # Database setup
│   ├── middleware/      # Express middleware
│   │   ├── passport.js  # Authentication strategies
│   │   └── setup.js     # Middleware configuration
│   └── routes/         # API routes
│       ├── auth.js     # Authentication routes
│       ├── providers.js # Provider management
│       └── service-requests.js # Service requests
│
├── uploads/            # Uploaded files (created automatically)
├── server.js          # Main server entry point
└── package.json       # Project dependencies
```

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## API Endpoints

### Authentication
- POST `/auth/register` - Register new user
- POST `/auth/login` - User login

### Providers
- GET `/providers` - List providers (supports search and geolocation)
- POST `/providers` - Register new provider
- POST `/providers/:id/documents` - Upload provider documents
- POST `/providers/:id/video` - Upload provider video
- GET `/providers/:id/video` - Get provider video

### Service Requests
- POST `/service-requests` - Create service request
- PUT `/service-requests/:id` - Update request status
- GET `/service-requests/:id` - Get request details

## Technologies Used

- Backend:
  - Node.js
  - Express
  - SQLite3
  - Passport.js
  - Multer (file uploads)
  - bcrypt (password hashing)

- Frontend:
  - HTML5
  - Tailwind CSS
  - JavaScript
  - Google Fonts
  - Font Awesome icons

## Features

### Provider Management
- Provider registration with service details
- Document and video upload capabilities
- Geolocation-based search
- Service categorization

### User Features
- User registration and authentication
- Service request creation
- Provider search and filtering
- Location-based provider discovery

### Video Recording
- In-browser video recording
- Provider presentation uploads
- Video playback support
- Multiple format support

### Security
- Password hashing
- Rate limiting
- Session management
- Secure file uploads

## Development

The application uses a modular architecture for better maintainability:

- Routes are separated by functionality
- Middleware is organized in dedicated files
- Configuration is centralized
- Database operations are isolated

## License

MIT License
