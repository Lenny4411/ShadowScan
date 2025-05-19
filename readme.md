## 🔍 Overview

ShadowScan est un outil puissant de scanning web qui combine deux modules essentiels pour la sécurité :

1. **EnvHunter** - Chasse aux fichiers .env et secrets exposés
2. **XSSAutoFuzz** - Détection avancée de vulnérabilités XSS

Créé par **Lenny**, cet outil est conçu pour les pentesters, chercheurs en sécurité et développeurs soucieux de la sécurité de leurs applications web.

## ✨ Features

### 🕵️ EnvHunter Module
- Scan multi-chemins pour les fichiers .env
- Détection de 15+ types de secrets (API keys, credentials, etc.)
- Patterns regex avancés pour l'extraction
- Support des variantes de fichiers (.env.local, .env.prod, etc.)

### 🎯 XSSAutoFuzz Module
- 20+ payloads XSS prédéfinis
- Fuzzing multi-paramètres (GET/POST)
- Détection de réflexion intelligente
- Multithreading pour performances accrues
- Analyse des formulaires HTML
- Crawling basique automatique
