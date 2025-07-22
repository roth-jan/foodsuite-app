# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# FoodSuite - Professional Kitchen Management System

## Overview
FoodSuite is a comprehensive kitchen management system with two parallel implementations:
1. **Active Implementation**: Node.js/Express backend with HTML/Bootstrap frontend (foodsuite-complete-app.html)
2. **Legacy/Reference**: .NET Core/Blazor implementation in src/ directory

The Node.js implementation is the primary focus for development and deployment.

## Architecture

### Backend (Node.js/Express)
- **Server**: Express.js with security middleware (Helmet, CORS, rate limiting)
- **Database**: Custom in-memory database with multi-tenant support (PostgreSQL optional via Docker)
- **API**: RESTful endpoints with Joi validation
- **Authentication**: Tenant-based isolation using headers
- **AI Engine**: Rule-based meal planning in routes/ai.js

### Frontend (HTML/Bootstrap)
- **UI Framework**: Bootstrap 5 with custom CSS
- **JavaScript**: Vanilla JS with modular functions
- **Components**: Modal-based forms and data tables
- **API Integration**: Fetch-based HTTP client
- **Drag & Drop**: Custom implementation for meal planning

### Key Files and Structure
- `server.js` - Main Express server with middleware configuration
- `routes/` - API route handlers (products, suppliers, orders, recipes, etc.)
- `routes/ai.js` - AI meal planning engine with rule-based logic
- `scripts/` - Database initialization and seeding scripts
- `foodsuite-complete-app.html` - Single-page frontend application
- `tests/` - Playwright and custom test files
- Docker configs: `docker-compose.yml` (production), `docker-compose.dev.yml` (development)

## Key Features

### Multi-Tenant Support
- Tenant isolation via `x-tenant-id` header
- Automatic data filtering by tenant
- Default tenant: 'demo'

### AI-Powered Meal Planning
The AI assistant in routes/ai.js provides:
- **5 Preset AI Modes**: cost_optimized, balanced_nutrition, variety, seasonal, inventory_based
- **Custom AI Mode Designer**: Create and save custom AI configurations with:
  - Weight sliders for cost, health, variety, and speed
  - Budget constraints (per meal and weekly)
  - Nutrition targets (calories, protein, etc.)
  - Ingredient/allergen exclusions (e.g., no pork/beef)
  - Category filtering
  - Cuisine preferences
- **Rule-based logic** (not external AI service)
- **Real-time plan adjustments**
- **Shopping list generation**
- **Order suggestions**

### Current Implementation Status
- ✅ All CRUD operations functional
- ✅ Drag & drop meal planning working
- ✅ AI meal plan generation working with 100+ recipes
- ✅ Multi-tenant isolation working
- ✅ Custom AI mode designer functional
- ✅ Health check endpoints implemented (/health, /api/health)
- ⚠️ Custom AI exclusions work ~80% (some edge cases with ingredient mappings)

## Development Commands

```bash
# Install dependencies
npm install

# Start development server (with nodemon)
npm run dev

# Start production server
npm start

# Docker commands
docker-compose -f docker-compose.dev.yml up -d  # Development with PostgreSQL
docker-compose up -d                             # Production setup
./docker-quick-start.ps1                         # Windows quick start
./docker-start.sh                                # Linux/Mac quick start

# Run Playwright tests
npx playwright test
npx playwright test --headed  # With browser window
npx playwright test --ui      # Interactive UI mode

# Test specific features
npx playwright test tests/test-ai-meal-planning.js
npx playwright test tests/test-drag-drop.js

# Database commands
npm run init-db      # Initialize database structure
npm run seed-db      # Load canteen test data
npm run reset-db     # Reset database to initial state

# Linting and type checking (if configured)
npm run lint         # Run ESLint
npm run lint:fix     # Auto-fix linting issues
```

## Docker Support

### Development Stack (docker-compose.dev.yml)
- PostgreSQL database for persistent storage
- Hot-reload with volume mounts
- Environment variables via .env file

### Production Stack (docker-compose.yml)
- Nginx reverse proxy with SSL
- Health checks configured
- Restart policies

### Environment Variables
```bash
DB_TYPE=postgres          # or 'memory' for in-memory
DB_PASSWORD=foodsuite123
NODE_ENV=development
DEFAULT_TENANT_ID=demo
```

## Server Configuration

### Rate Limiting
Currently disabled for testing. To re-enable:
```javascript
app.use(limiter); // Uncomment in server.js line 56
```

### CORS Configuration
Configured to accept requests from:
- http://localhost:3000
- http://127.0.0.1:3000
- file:// URLs
- null origin

## API Endpoints

### Health Check Endpoints
- `GET /health` - Basic health check for Docker
- `GET /api/health` - Detailed API health status

### AI Endpoints
- `POST /api/ai/suggest-meals` - Generate AI meal plan
  ```json
  {
    "mode": "variety",
    "weekNumber": 1,
    "currentPlan": {},
    "customConfig": {  // Optional for custom mode
      "type": "custom",
      "weights": { "cost": 0.8, "health": 0.2, "variety": 0.5, "speed": 0.3 },
      "exclusions": {
        "ingredients": ["Schwein", "Rind"],
        "allergens": [],
        "categories": []
      },
      "budget": { "maxCostPerMeal": 3.00 },
      "nutrition": { "minCalories": 500, "maxCalories": 800 }
    }
  }
  ```

### Standard CRUD Endpoints
All endpoints require `x-tenant-id` header:
- `/api/products` - Product management
- `/api/suppliers` - Supplier management
- `/api/orders` - Order management
- `/api/recipes` - Recipe management
- `/api/inventory` - Inventory tracking
- `/api/mealplans` - Meal plan management
- `/api/analytics` - Analytics and reporting
- `/api/auth` - Authentication (no tenant header required)
- `/api/price-monitoring` - Price monitoring and alerts

## Frontend Key Functions

### Meal Planning
- `loadMealPlanning()` - Initializes meal planning view
- `generateAIWeekMenu()` - Generates AI meal plan (supports custom configs)
- `createMealCalendar()` - Renders drag & drop calendar
- `getCurrentAIMode()` - Gets selected AI assistant mode
- `buildCustomConfig()` - Creates custom AI configuration from UI inputs
- `addCustomModeButton()` - Adds saved custom mode to UI
- `loadSavedCustomModes()` - Loads custom modes from localStorage

### API Integration Pattern
```javascript
const response = await fetch(`${API_BASE_URL}/endpoint`, {
    headers: {
        'Content-Type': 'application/json',
        'x-tenant-id': TENANT_ID
    },
    // ... options
});
```

## Testing Strategy

### Local Testing
1. Start server: `node server.js`
2. Open browser: http://localhost:3000
3. Click "KI-Speiseplanung" tab
4. AI will auto-generate meal plan if calendar is empty

### Automated Testing
```bash
# Full test suite
npm test

# Specific test files
npx playwright test tests/test-ai-meal-planning.js
npx playwright test tests/test-drag-drop.js

# Custom mode testing
node test-custom-mode-simple.js
node test-health.js
```

## Deployment

### AWS EC2 Instance
- Running at: http://3.120.41.138:3000
- Uses PM2 for process management
- Nginx reverse proxy configured

### Local Development
- Default port: 3000
- In-memory database (resets on restart) or PostgreSQL via Docker
- No external dependencies required

## Important Implementation Notes

1. **AI is Rule-Based**: The "AI" in routes/ai.js uses algorithms, not ML models
2. **Test Data Language**: All test data is in German (products, recipes, suppliers)
3. **Database Persistence**: In-memory by default, PostgreSQL optional via Docker
4. **Auto-Generation**: Meal plans auto-generate when opening empty calendar
5. **Drag & Drop**: Fully functional between calendar cells and from recipe library
6. **Custom Modes**: Saved in browser localStorage, persist across sessions
7. **Health Checks**: Required for Docker deployments at /health and /api/health

## Code Conventions

### Backend
- Use Joi for validation
- Return `{ error: "message" }` for errors
- Log transactions for inventory changes
- Use async/await consistently
- All routes return JSON with consistent structure
- Use proper HTTP status codes (200, 400, 404, 500)
- Handle multi-tenant isolation via tenant middleware

### Frontend
- Modal-based forms for all data entry
- Show toast notifications for user feedback
- Refresh data after successful operations
- Maintain vanilla JavaScript (no frameworks)
- Use Bootstrap 5 CSS classes for styling
- Implement loading states for async operations

### Error Handling
```javascript
// Backend error response format
{ error: "Descriptive error message" }

// Frontend error handling pattern
try {
    const response = await fetch(url, options);
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Request failed');
    }
    return await response.json();
} catch (error) {
    showToast(error.message, 'error');
}
```

## Recent Changes

### 2025-07-19
- Added custom AI mode designer with exclusions and preferences
- Implemented health check endpoints for Docker support
- Created Docker development stack with PostgreSQL
- Fixed ingredient exclusion mappings for German recipes
- Added Windows PowerShell and Linux/Mac quick start scripts

### 2025-07-18
- Fixed CORS configuration for file:// URLs
- Disabled rate limiting for testing
- Added auto-generation of meal plans on tab load
- Fixed API response structure mismatch in frontend

## Known Issues & Workarounds

### Custom AI Mode Designer
- Exclusions work ~80% - some dishes with meat ingredients aren't caught
- Workaround: Check generated plans and manually adjust
- Fix planned: Enhance INGREDIENT_MAPPINGS in routes/ai.js

### Docker on Windows
- Use PowerShell scripts (*.ps1) instead of bash scripts
- Git Bash may have issues with paths - use native PowerShell

### Testing
- Server must be running before tests: `node server.js`
- Use test-custom-mode-simple.js to verify exclusions
- Use test-health.js to verify health endpoints
- Playwright tests require server to be running on port 3000
- Many test files are numbered/versioned - use latest versions
- Test files cover: drag-drop, AI functionality, auth system, API integration