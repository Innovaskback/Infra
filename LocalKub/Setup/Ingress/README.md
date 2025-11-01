# Local Kubernetes Cluster Setup Guide

Complete infrastructure setup for deploying applications on a local Kubernetes cluster with Kafka, Zookeeper, SQL Server, and HTTPS ingress.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
  - [1. Infrastructure Setup](#1-infrastructure-setup)
  - [2. Kafka & Zookeeper](#2-kafka--zookeeper)
  - [3. SQL Server](#3-sql-server)
  - [4. Certificate Manager](#4-certificate-manager)
  - [5. Application Deployment](#5-application-deployment)
- [Configuration Files](#configuration-files)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

---

## 🎯 Overview

This repository contains production-ready Kubernetes manifests for deploying a complete microservices infrastructure including:

- **Kafka Cluster**: 3-node Kafka cluster for event streaming
- **Zookeeper Cluster**: 3-node Zookeeper ensemble for Kafka coordination
- **SQL Server**: Microsoft SQL Server 2022 Express with persistent storage
- **Ingress Controller**: Nginx ingress with automatic SSL/TLS certificates
- **Cert-Manager**: Automated Let's Encrypt certificate management
- **MetalLB**: Load balancer for bare-metal Kubernetes

---

## ✅ Prerequisites

### Required Software
- **Kubernetes Cluster**: MicroK8s, K3s, or minikube (minimum CPU: 4 cores, RAM: 8GB)
- **kubectl**: Kubernetes command-line tool
- **gettext**: For environment variable substitution (`envsubst`)

### Network Requirements
- Static external IP address for LoadBalancer services
- DNS records pointing to your cluster IP:
  - `kub.innovask.com` → `69.10.55.229`

### Minimum System Resources
```
CPU:    4 cores (8 cores recommended)
RAM:    8GB (16GB recommended)
Disk:   50GB free space for persistent volumes
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     External Traffic                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Nginx Ingress Controller                       │
│                  (Port 80/443)                              │
│         ┌──────────────────────────────┐                    │
│         │   Cert-Manager (Let's Encrypt)│                   │
│         └──────────────────────────────┘                    │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Auth API   │  │  Other APIs  │  │  Frontend    │
│ (Production) │  │ (Production) │  │    Apps      │
└──────┬───────┘  └──────┬───────┘  └──────────────┘
       │                 │
       └────────┬────────┘
                │
    ┌───────────┼───────────┐
    ▼           ▼           ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│ Kafka-0 │ │ Kafka-1 │ │ Kafka-2 │
└────┬────┘ └────┬────┘ └────┬────┘
     │           │           │
┌────┴───────────┴───────────┴────┐
│      Zookeeper Cluster          │
│  ┌─────┐  ┌─────┐  ┌─────┐     │
│  │ ZK-0│  │ ZK-1│  │ ZK-2│     │
│  └─────┘  └─────┘  └─────┘     │
└─────────────────────────────────┘
          │
          ▼
┌──────────────────┐
│   SQL Server     │
│  (Port 31434)    │
└──────────────────┘
```

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
cd E:\Infra\LocalKub\Setup

# 2. Install infrastructure components
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/baremetal/deploy.yaml
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.8/config/manifests/metallb-native.yaml

# 3. Create namespaces
kubectl create namespace kafka
kubectl create namespace production
kubectl create namespace sqlserver

# 4. Deploy Kafka & Zookeeper
kubectl apply -f kafka/StorageSetup.yaml
kubectl wait --for=condition=complete job/create-kafka-zookeeper-storage -n kafka --timeout=120s
kubectl apply -f kafka/kafkazookeeper.yaml
kubectl wait --for=condition=ready pod -l app=zookeeper -n kafka --timeout=300s
kubectl apply -f kafka/kafka.yaml

# 5. Deploy SQL Server
kubectl apply -f SqlServerMkDir.yaml
kubectl wait --for=condition=complete job/create-sqlserver-directory -n sqlserver --timeout=60s
kubectl apply -f Sqlserver.yaml

# 6. Setup Cert-Manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.1/cert-manager.yaml
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=cert-manager -n cert-manager --timeout=300s
kubectl apply -f Ingress/Cluster-issuer.yaml

# 7. Deploy applications
export APP_NAME="ba-auth-api"
export KUBERNETES_NAMESPACE="production"
export DOCKER_IMAGE="tawabsoft/innovask"
export DOCKER_TAG="auth-be-pr"
export DEPLOYMENT_TIMESTAMP="$(date +%s)"

envsubst < Ingress/AuthAPI.yaml | kubectl apply -f -
envsubst < Ingress/Ingress.yaml | kubectl apply -f -
```

---

## 📖 Detailed Setup

### 1. Infrastructure Setup

#### Install Nginx Ingress Controller
```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/baremetal/deploy.yaml

# Verify installation
kubectl get pods -n ingress-nginx
```

#### Install MetalLB Load Balancer
```bash
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.8/config/manifests/metallb-native.yaml

# Configure IP address pool (adjust as needed)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 69.10.55.229/32
EOF
```

---

### 2. Kafka & Zookeeper

#### Deploy Storage and Zookeeper
```bash
# Apply storage configuration (creates PVs and directories)
kubectl apply -f kafka/StorageSetup.yaml

# Wait for storage setup to complete
kubectl wait --for=condition=complete job/create-kafka-zookeeper-storage -n kafka --timeout=120s

# Verify PersistentVolumes
kubectl get pv

# Deploy Zookeeper (3 replicas)
kubectl apply -f kafka/kafkazookeeper.yaml

# Monitor Zookeeper pods
kubectl get pods -n kafka -w
```

#### Deploy Kafka
```bash
# Wait for all Zookeeper pods to be ready
kubectl wait --for=condition=ready pod -l app=zookeeper -n kafka --timeout=300s

# Deploy Kafka (3 replicas)
kubectl apply -f kafka/kafka.yaml

# Monitor Kafka pods
kubectl get pods -n kafka -w
```

#### Verify Kafka Cluster
```bash
# Check pod status
kubectl get pods -n kafka -o wide

# Check logs
kubectl logs kafka-0 -n kafka
kubectl logs zookeeper-0 -n kafka

# Expected output: 3 Kafka pods and 3 Zookeeper pods running
```

**Configuration Details:**
- **Replication Factor**: 3 (production-ready)
- **Min In-Sync Replicas**: 2
- **Storage**: 10Gi per Kafka broker, 5Gi per Zookeeper node
- **Pod Management**: OrderedReady for stable startup

---

### 3. SQL Server

#### Deploy SQL Server
```bash
# Create storage directory
kubectl apply -f SqlServerMkDir.yaml

# Wait for directory creation
kubectl wait --for=condition=complete job/create-sqlserver-directory -n sqlserver --timeout=60s

# Deploy SQL Server
kubectl apply -f Sqlserver.yaml

# Monitor deployment
kubectl get pods -n sqlserver -w
```

#### Access SQL Server

**From outside the cluster (SSMS, Azure Data Studio):**
```
Server:   69.10.55.229,31434
Username: sa
Password: <from sqlserver-secret>
Database: Innovask_Serilog
```

**From inside the cluster (application connections):**
```
Server:   sqlserver-internal.sqlserver.svc.cluster.local,1433
Username: sa
Password: <from sqlserver-secret>
Database: Innovask_Serilog
```

**Connection String Example:**
```csharp
"Server=sqlserver-internal.sqlserver.svc.cluster.local,1433;Database=Innovask_Serilog;User Id=sa;Password=<password>;TrustServerCertificate=True;"
```

---

### 4. Certificate Manager

#### Install Cert-Manager
```bash
# Install cert-manager CRDs and components
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.1/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl -n cert-manager rollout status deploy/cert-manager --timeout=180s
kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=180s
kubectl -n cert-manager rollout status deploy/cert-manager-cainjector --timeout=180s
```

#### Configure Let's Encrypt Issuer
```bash
# Apply ClusterIssuer for Let's Encrypt
kubectl apply -f Ingress/Cluster-issuer.yaml

# Verify ClusterIssuer
kubectl get clusterissuer
```

**Note:** The ClusterIssuer uses Let's Encrypt production server. For testing, use the staging server to avoid rate limits.

---

### 5. Application Deployment

#### Create Docker Registry Secret
```bash
kubectl create secret docker-registry docker-hub-secret \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username=<your-username> \
  --docker-password=<your-password> \
  --docker-email=<your-email> \
  -n production
```

#### Deploy Auth API
```bash
# Set environment variables
export APP_NAME="ba-auth-api"
export KUBERNETES_NAMESPACE="production"
export DOCKER_IMAGE="tawabsoft/innovask"
export DOCKER_TAG="auth-be-pr"
export DEPLOYMENT_TIMESTAMP="$(date +%s)"

# Apply deployment
envsubst < Ingress/AuthAPI.yaml | kubectl apply -f -

# Apply ingress
envsubst < Ingress/Ingress.yaml | kubectl apply -f -

# Monitor deployment
kubectl rollout status deployment/$APP_NAME -n $KUBERNETES_NAMESPACE
```

#### Verify Certificate
```bash
# Check certificate status
kubectl get certificate -n production

# Check certificate details
kubectl describe certificate ba-auth-api-certificate -n production

# Expected: Certificate should be in "Ready" state
```

---

## 📁 Configuration Files

### Kafka & Zookeeper
| File | Description |
|------|-------------|
| `kafka/StorageSetup.yaml` | Creates StorageClass, PersistentVolumes, and storage directories |
| `kafka/kafkazookeeper.yaml` | Zookeeper StatefulSet (3 replicas) with persistent storage |
| `kafka/kafka.yaml` | Kafka StatefulSet (3 replicas) with production settings |

### SQL Server
| File | Description |
|------|-------------|
| `Sqlserver.yaml` | SQL Server deployment with PV, Secret, and Services |
| `SqlServerMkDir.yaml` | Job to create storage directory on host |

### Ingress & Certificates
| File | Description |
|------|-------------|
| `Ingress/Cluster-issuer.yaml` | Let's Encrypt ClusterIssuer for cert-manager |
| `Ingress/Ingress.yaml` | Ingress rules with TLS and CORS configuration |
| `Ingress/AuthAPI.yaml` | Auth API deployment with HPA and PDB |

### Additional Files
| File | Description |
|------|-------------|
| `Ingress/NewSqlServer.yaml` | Alternative SQL Server configuration with LoadBalancer |
| `Ingress/AuthAPIWorkFlow.yml` | GitHub Actions workflow for CI/CD |
| `Ingress/Kub.yaml` | MicroK8s kubeconfig file |

---

## 🔧 Troubleshooting

### Kafka Issues

**Pods stuck in Pending:**
```bash
# Check PersistentVolume status
kubectl get pv
kubectl get pvc -n kafka

# Ensure storage job completed
kubectl logs job/create-kafka-zookeeper-storage -n kafka
```

**Kafka can't connect to Zookeeper:**
```bash
# Verify Zookeeper is running
kubectl get pods -n kafka -l app=zookeeper

# Check Zookeeper logs
kubectl logs zookeeper-0 -n kafka

# Test Zookeeper connectivity
kubectl exec -it kafka-0 -n kafka -- nc -zv zookeeper-0.zookeeper-headless.kafka.svc.cluster.local 2181
```

### SQL Server Issues

**Can't connect from SSMS:**
```bash
# Verify NodePort service
kubectl get svc sqlserver-external -n sqlserver

# Check if port 31434 is accessible
telnet 69.10.55.229 31434

# Check SQL Server logs
kubectl logs deployment/sqlserver -n sqlserver -c sqlserver
```

**Database not initialized:**
```bash
# Check init sidecar logs
kubectl logs deployment/sqlserver -n sqlserver -c sqlserver-init
```

### Certificate Issues

**Certificate not issuing:**
```bash
# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Check certificate status
kubectl describe certificate ba-auth-api-certificate -n production

# Check certificate request
kubectl get certificaterequest -n production
kubectl describe certificaterequest <name> -n production

# Check challenges
kubectl get challenge -n production
```

**Common causes:**
- DNS not pointing to correct IP
- Ingress not routing correctly
- Firewall blocking port 80 (required for HTTP-01 challenge)

### General Debug Commands

```bash
# Check all pods status
kubectl get pods -A

# Check events
kubectl get events -n <namespace> --sort-by='.lastTimestamp'

# Check logs
kubectl logs <pod-name> -n <namespace>

# Describe resources
kubectl describe pod <pod-name> -n <namespace>
kubectl describe pvc <pvc-name> -n <namespace>

# Check resource usage
kubectl top nodes
kubectl top pods -n <namespace>
```

---

## 🔒 Security Considerations

### Immediate Actions Required

1. **Change Default Passwords:**
   ```bash
   # Update SQL Server password
   kubectl create secret generic sqlserver-secret \
     --from-literal=sa-password='<strong-password>' \
     -n sqlserver --dry-run=client -o yaml | kubectl apply -f -

   # Restart SQL Server to apply
   kubectl rollout restart deployment/sqlserver -n sqlserver
   ```

2. **Secure Docker Registry Credentials:**
   ```bash
   # Store credentials in Kubernetes Secrets instead of command line
   kubectl create secret docker-registry docker-hub-secret \
     --from-file=.dockerconfigjson=$HOME/.docker/config.json \
     -n production
   ```

3. **Review NetworkPolicy:**
   ```bash
   # SQL Server has a NetworkPolicy defined
   # Review and adjust as needed in Sqlserver.yaml
   kubectl get networkpolicy -n sqlserver
   ```

### Production Hardening

- **Enable RBAC**: Configure Role-Based Access Control
- **Pod Security Policies**: Restrict privileged containers
- **Network Policies**: Implement strict namespace isolation
- **Resource Limits**: Set appropriate limits for all pods
- **Monitoring**: Deploy Prometheus and Grafana
- **Backup Strategy**: Implement regular backups for SQL Server and Kafka
- **Secret Management**: Use external secret management (Vault, Sealed Secrets)

---

## 📊 Resource Requirements Summary

| Component | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit | Storage |
|-----------|----------|-------------|-----------|----------------|--------------|---------|
| Kafka | 3 | 250m | 1000m | 1Gi | 2Gi | 10Gi each |
| Zookeeper | 3 | 500m | 1000m | 1Gi | 2Gi | 5Gi + 5Gi logs |
| SQL Server | 1 | 500m | 2000m | 2Gi | 4Gi | 20Gi |
| Auth API | 1-5 (HPA) | 500m | 1000m | 512Mi | 1Gi | - |
| **Total** | **8-10** | **~3 cores** | **~9 cores** | **~9Gi** | **~19Gi** | **~70Gi** |

---

## 📝 Notes

- **Kafka Replication**: Set to 3 for production. Adjust in `kafka/kafka.yaml` if needed.
- **SQL Server Edition**: Using Express edition (free). Upgrade to Standard/Enterprise for production.
- **Certificate Renewal**: Automatic via cert-manager (30 days before expiry).
- **Persistent Storage**: Uses local storage class. Consider network storage (NFS, Ceph) for multi-node clusters.
- **Backup**: Implement backup strategies for Kafka topics and SQL Server databases.

---

## 🤝 Contributing

For issues or improvements, please review the configuration files and ensure:
- All secrets are properly configured
- DNS records point to correct IPs
- Resource limits match your cluster capacity
- Storage paths exist on host machines

---

## 📚 Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Kafka Documentation](https://kafka.apache.org/documentation/)
- [Cert-Manager Documentation](https://cert-manager.io/docs/)
- [Nginx Ingress Documentation](https://kubernetes.github.io/ingress-nginx/)
- [SQL Server on Kubernetes](https://learn.microsoft.com/en-us/sql/linux/sql-server-linux-kubernetes-deploy)

---

**Last Updated:** 2025-10-30
**Kubernetes Version:** 1.28+
**Tested On:** MicroK8s 1.28, K3s 1.28
