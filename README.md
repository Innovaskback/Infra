# TawabSoft Infrastructure Repository

This repository contains Kubernetes deployment configurations and infrastructure management scripts for the TawabSoft educational platform across multiple cloud providers and environments.

## Overview

The TawabSoft platform is a comprehensive educational system with multiple microservices including:
- **Frontend Services**: Dashboard, Authentication, Assessment, Video Player, Products, etc.
- **Backend Services**: API services for each frontend component
- **Infrastructure**: Load balancers, ingress controllers, database services
- **Video Processing**: AI course processing and video transcoding services

## Cloud Providers & Environments

### 🌐 DigitalOcean
- **Production Environment**: Full production deployment
- **Testing Environment**: Beta/testing deployments
- **KSA Environment**: Saudi Arabia specific deployments

### ☁️ Google Cloud Platform (GCP)
- **GKE Cluster**: `TawabSoft` in `me-central2` region
- **Project**: `TawabSoft-edu-platform`
- **KSA Environment**: Regional deployments for Saudi Arabia

### 🏠 Local Development
- **MicroK8s**: Local Kubernetes cluster setup
- **Load Balancer**: Nginx-based load balancing
- **Kafka**: Message streaming infrastructure

## Repository Structure

```
├── DigitalOcean/          # DigitalOcean Kubernetes deployments
│   ├── ingress/          # Ingress controllers and routing
│   ├── service/          # Application services
│   │   ├── back/         # Backend microservices
│   │   ├── front/        # Frontend applications
│   │   └── ksa/          # KSA-specific services
│   └── sql/              # Database configurations
├── Google/               # Google Cloud Platform deployments
│   ├── Service/          # GCP service configurations
│   ├── ingress/          # GCP ingress controllers
│   └── Back/             # Backend services for GCP
├── LocalKub/             # Local development setup
│   ├── Setup/            # Infrastructure setup scripts
│   │   ├── Balancer/     # Load balancer configuration
│   │   ├── HlsNginx/     # HLS streaming setup
│   │   └── kafka/        # Kafka cluster setup
│   └── *.yaml            # Local service deployments
└── apply.yaml            # Main deployment script
```

## Quick Start

### Prerequisites
- `kubectl` installed and configured
- Access to target Kubernetes clusters
- Docker registry credentials

### DigitalOcean Deployment
```bash
# Apply ingress controllers
kubectl apply -f DigitalOcean/ingress/ingress-prod.yml
kubectl apply -f DigitalOcean/ingress/ingress-beta.yml

# Deploy services
kubectl apply -f DigitalOcean/service/back/b_auth-prod.yml
kubectl apply -f DigitalOcean/service/front/auth-prod.yml
# ... (see apply.yaml for complete list)
```

### Google Cloud Deployment
```bash
# Authenticate with GCP
gcloud auth login
gcloud container clusters get-credentials TawabSoft --zone me-central2 --project TawabSoft-edu-platform

# Deploy KSA services
kubectl apply -f Google/ingress-ksa.yml
kubectl apply -f Google/b_auth-ksa.yml
kubectl apply -f Google/videoplayer-ksa.yml
```

### Local Development
```bash
# Setup MicroK8s
sudo snap install kubectl --classic
sudo microk8s config > ~/.kube/config

# Deploy local services
kubectl apply -f LocalKub/VideoConvert.yaml
kubectl apply -f LocalKub/aicourseprocessing.yaml
```

## Services Overview

### Frontend Services
- **Dashboard**: Main user interface
- **Authentication**: User login/registration
- **Assessment**: Quiz and assessment tools
- **Video Player**: Educational video streaming
- **Products**: Course catalog and management
- **Leaderboard**: Gamification features
- **Infographic**: Data visualization
- **Admin**: Administrative interface

### Backend Services
- **b_auth**: Authentication API
- **b_dashboard**: Dashboard API
- **b_assessment**: Assessment API
- **b_videoplayer**: Video streaming API
- **b_products**: Products API
- **b_aiassessment**: AI-powered assessment
- **ba-sharing**: Content sharing API

### Infrastructure Services
- **Load Balancer**: Nginx-based traffic distribution
- **Ingress Controllers**: SSL termination and routing
- **Video Processing**: AI course processing and transcoding
- **Database**: SQL Server with high availability
- **Message Queue**: Kafka for event streaming

## Environment Management

### Namespaces
- `production`: Production environment
- `testing`: Testing/beta environment
- `sql-ha`: Database high availability

### Secrets Management
```bash
# Create Docker registry secret
kubectl create secret docker-registry regcred \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username=TawabSofttawab \
  --docker-password=<token> \
  --docker-email=m_tawab@TawabSoft.com \
  -n testing
```

## Monitoring & Health Checks

### Health Endpoints
- Load Balancer: `http://69.10.55.230/health`
- Nginx Status: `http://127.0.0.1:8080/nginx_status`
- JSON Health: `http://127.0.0.1:8080/health/json`

### Useful Commands
```bash
# Check all resources
kubectl get namespaces --sort-by=.metadata.creationTimestamp
kubectl get deployment --all-namespaces
kubectl get ingress -A
kubectl get pods -A

# Restart deployments
kubectl rollout restart deploy <deployment-name> -n <namespace>
kubectl rollout status deployment/<deployment-name> -n <namespace>
```

## Development Workflow

### Git Repository Structure
- **TawabSoftBackEnd**: Backend microservices
- **TawabSoftFrontEnd**: Frontend applications
- **HajjFrontend**: Specialized frontend for Hajj platform

### Local Development Setup
1. Clone all required repositories (see `Git.txt`)
2. Install dependencies (`npm install` for frontend services)
3. Configure local Kubernetes cluster
4. Deploy services using provided YAML files

## Security Notes

⚠️ **Important**: This repository contains sensitive configuration files including:
- API keys and tokens
- Database credentials
- SSL certificates
- Service account keys

Ensure proper access controls and never commit sensitive data to version control.

## Support

For infrastructure issues or deployment questions, contact the DevOps team or refer to the internal documentation.
