# FoodSuite MVP - Multi-Tenant SaaS Warenwirtschaftslösung

Eine moderne, cloudbasierte Warenwirtschaftslösung für Großküchen mit KI-gestütztem Preisvergleich.

## 🚀 Quick Start mit Docker

### Voraussetzungen
- Docker Desktop installiert und gestartet
- Mindestens 4GB RAM verfügbar
- Ports 1433, 5000, 6379 verfügbar

### Anwendung starten

```bash
# Repository klonen oder Dateien verfügbar machen
cd /path/to/foodsuite

# Container mit Docker Compose starten
docker-compose up -d

# Logs verfolgen
docker-compose logs -f
```

### Zugriff auf die Anwendung

- **Swagger API**: http://localhost:5000/swagger
- **SQL Server**: localhost:1433 (sa / FoodSuite123!)
- **Redis**: localhost:6379

## 🏗️ Architektur

### Clean Architecture Layers
- **Domain**: Geschäftslogik und Entitäten
- **Application**: Use Cases mit CQRS/MediatR
- **Infrastructure**: EF Core, Authentication, Services
- **WebAPI**: REST Endpoints mit OpenAPI
- **Blazor**: Progressive Web App Frontend

### Multi-Tenant SaaS Features
- ✅ Row-Level Security mit TenantId
- ✅ Automatische Datenisolation
- ✅ Mandanten-spezifische Konfiguration
- ✅ JWT-basierte Authentifizierung (geplant)
- ✅ Role-Based Access Control

## 📊 Implementierter Umfang (Modul 1)

### ✅ Domain Model
- Vollständiges UML-Diagramm
- Multi-Tenant BaseEntity
- Value Objects (Money, Address, etc.)
- Aggregate Roots mit Domain Events

### ✅ API Design
- OpenAPI 3.0 Spezifikation
- RESTful Endpoints
- Paginierung und Filterung
- Konsistente Error Handling

### ✅ Database Schema
- EF Core Konfigurationen
- Optimierte Indizes
- Row-Level Security Support
- SQL Server Migration Scripts

### ✅ Frontend Components
- Responsive Blazor UI
- Product Management
- Dashboard mit Metriken
- Multi-Tenant Navigation

## 🛠️ Development

### Lokale Entwicklung

```bash
# .NET SDK 8.0 installieren
# SQL Server lokal oder Docker verwenden

# Dependencies installieren
dotnet restore

# Datenbank erstellen
dotnet ef database update --project src/FoodSuite.Infrastructure

# WebAPI starten
dotnet run --project src/FoodSuite.WebAPI

# Blazor App starten (separates Terminal)
dotnet run --project src/FoodSuite.Blazor
```

### Container Build

```bash
# Image bauen
docker build -t foodsuite:latest .

# Container starten
docker run -p 5000:5000 foodsuite:latest
```

## 📈 Roadmap - Weitere Module

1. **Lieferantenverwaltung** - Supplier Management mit Bewertungen
2. **Bestellwesen** - Automatisierte Beschaffung mit Workflows
3. **Lagerverwaltung** - Real-time Inventory mit Mindestbeständen
4. **Rezeptverwaltung** - Skalierbare Rezepte mit Nährwerten
5. **Speiseplanung** - KI-unterstützte Menüplanung
6. **Kostenkalkulation** - Dynamische Preisberechnung
7. **Benchmark-Analytics** - Marktvergleich mit Azure OpenAI
8. **Reporting & BI** - Power BI Integration
9. **Mobile App** - Native iOS/Android mit Offline-Support

## 🔧 Konfiguration

### Umgebungsvariablen

```bash
ASPNETCORE_ENVIRONMENT=Development
ConnectionStrings__DefaultConnection=Server=...
JWT__Secret=your-jwt-secret
Redis__ConnectionString=localhost:6379
```

### Feature Flags

```json
{
  "Features": {
    "EnableBenchmark": true,
    "EnableMultiTenant": true,
    "EnableCaching": true
  }
}
```

## 📝 API Dokumentation

Nach dem Start verfügbar unter:
- Swagger UI: http://localhost:5000/swagger
- OpenAPI JSON: http://localhost:5000/swagger/v1/swagger.json

## 🧪 Testing

```bash
# Unit Tests
dotnet test

# Integration Tests
dotnet test --filter Category=Integration

# E2E Tests (Playwright)
dotnet test --filter Category=E2E
```

## 📞 Support

Für Fragen und Support:
- GitHub Issues: [Repository Issues](https://github.com/your-org/foodsuite/issues)
- Dokumentation: [Wiki](https://github.com/your-org/foodsuite/wiki)

## 📄 License

Copyright © 2024 FoodSuite. Alle Rechte vorbehalten.