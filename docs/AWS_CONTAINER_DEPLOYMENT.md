# AccessLens AI — AWS Container Deployment Guide (AWS App Runner & Amazon ECS)

> **Deployment Target**: AWS App Runner / Amazon ECS (Fargate)  
> **Container Base**: Python 3.12 + Playwright Chromium + axe-core 4.13.0  
> **Hackathon Requirement**: Pairs Strands Decider 2B (`#policy`) with Amazon Bedrock on AWS  
> **Credit**: Built with the AWS User Group Madurai Strands Decider hackathon kit  

---

## 1. Why Container Deployment Solves `BROWSER_UNAVAILABLE`

Serverless platforms like Vercel Functions run in ephemeral sandboxes with:
- Strict unzipped payload limits (250 MB).
- Missing Linux desktop shared libraries (`libnss3.so`, `libatk-1.0.so.0`, `libXcomposite.so.1`).
- Discarded home directory caches (`~/.cache/ms-playwright/`) between build and execution.

Deploying AccessLens AI inside a Docker container on **AWS App Runner** or **Amazon ECS (Fargate)** bundles both the Python application, the official Chromium browser executable, and all native Linux OS dependencies into a single deployable image. This enables real headless browser automation and axe-core accessibility auditing on live websites.

---

## 2. Docker Architecture Overview

The provided [`Dockerfile`](../Dockerfile) implements:
1. **Base Image**: `python:3.12-slim-bookworm`.
2. **Matching Browser Installation**: Executes `playwright install --with-deps chromium`, ensuring the exact matching Chromium revision and Linux dependencies are installed at build time.
3. **Dedicated Shared Path**: Configures `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright` so any non-root user can launch Chromium.
4. **Least-Privilege Security**: Runs as an unprivileged user `accesslens` (`USER accesslens`).
5. **Clean Build Context**: Strictly excludes credentials, `.env` files, and local databases via [`.dockerignore`](../.dockerignore).
6. **Built-in Health Check**: Validates `/api/health` every 30 seconds.

---

## 3. Local Testing with Docker

Before deploying to AWS, test the container locally:

```bash
# 1. Build the Docker image
docker build -t accesslens-ai:latest .

# 2. Run the container locally (port 8000)
docker run -p 8000:8000 \
  -e LLM_PROVIDER=disabled \
  -e DECIDER_MODE=ugmdu \
  -e DECIDER_URL=https://da25tnxy06gjk.cloudfront.net \
  -e DECIDER_API_KEY="your-decider-api-key" \
  accesslens-ai:latest

# 3. Test the container endpoints
curl http://localhost:8000/api/health
```

---

## 4. Deploying to AWS App Runner (Recommended)

AWS App Runner is a fully managed service that deploys containerized web applications with automatic load balancing, TLS encryption, and horizontal scaling.

### Step 4.1: Push Image to Amazon Elastic Container Registry (ECR)

```bash
# 1. Set your AWS Region and Account ID
AWS_REGION="us-east-1"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 2. Create ECR repository
aws ecr create-repository \
  --repository-name accesslens-ai \
  --region $AWS_REGION

# 3. Authenticate Docker with Amazon ECR
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# 4. Tag and push the image
docker tag accesslens-ai:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/accesslens-ai:latest
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/accesslens-ai:latest
```

### Step 4.2: Create the App Runner Service

1. Open the **AWS App Runner Console** at [console.aws.amazon.com/apprunner](https://console.aws.amazon.com/apprunner).
2. Choose **Create service**.
3. **Source**: Select **Container registry** -> **Amazon ECR**.
4. **Container image URI**: Select `accesslens-ai:latest`.
5. **Deployment settings**: Choose **Automatic** (or Manual).
6. **ECR access role**: Allow App Runner to create or use the default `AppRunnerECRAccessRole`.
7. **Configure service**:
   - **Service name**: `accesslens-ai`
   - **Virtual CPU & Memory**: `1 vCPU`, `2 GB` (minimum recommended for Playwright Chromium).
   - **Port**: `8000`
   - **Health check path**: `/api/health`
8. **Environment variables**:
   - `LLM_PROVIDER`: `bedrock` (or `disabled` for zero-cloud-cost evaluation)
   - `AWS_REGION`: `us-east-1`
   - `BEDROCK_MODEL_ID`: `us.amazon.nova-pro-v1:0`
   - `DECIDER_MODE`: `ugmdu`
   - `DECIDER_URL`: `https://da25tnxy06gjk.cloudfront.net`
   - `DECIDER_API_KEY`: *(your AWS User Group Madurai Decider key)*
   - `DECIDER_CONFIDENCE_THRESHOLD`: `0.70`
9. **Instance role (Security)**: Attach an IAM Role with Amazon Bedrock permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": "*"
       }
     ]
   }
   ```
10. Click **Create & deploy**. App Runner provides an HTTPS URL (e.g., `https://xxxxxxxx.us-east-1.awsapprunner.com`).

---

## 5. Deploying to Amazon ECS (Fargate)

If your organization uses Amazon ECS:

1. **Task Definition**:
   - Launch type: `FARGATE`.
   - OS: `Linux/X86_64`.
   - CPU: `1 vCPU` (1024), Memory: `2 GB` (2048).
   - Container Port: `8000`.
   - Health check command: `["CMD-SHELL", "curl -f http://localhost:8000/api/health || exit 1"]`.
2. **Task Execution Role**: Grants ECS permission to pull from ECR and send logs to CloudWatch.
3. **Task Role**: Grants permissions to invoke Amazon Bedrock (`bedrock:InvokeModel`).
4. **Service & Load Balancer**: Attach an Application Load Balancer (ALB) listening on port 443 with target group pointing to port 8000.

---

## 6. Live Verification Checklist

Once deployed to AWS App Runner or Amazon ECS:

1. **Health Check**:
   ```bash
   curl -s https://<YOUR_APP_RUNNER_URL>/api/health | jq .
   ```
   *Expected response*: `{"status": "healthy", "engine": "axe-core 4.13.0 via Playwright Chromium", "ssrf_protection": "enabled", ...}`.
2. **Civic Fixture Audit**:
   - Open the web dashboard in your browser.
   - Select preset: **Scholarship Portal (Local Fixture — Barriers)** (`fixture:civic_scholarship_portal`).
   - Click **Run Audit**. Verify that 6 real accessibility violations are detected by axe-core.
3. **Live Website Audit**:
   - Enter `https://www.w3.org/WAI/standards-guidelines/wcag/` and click **Run Audit**.
   - Verify Chromium renders the page, executes axe-core, and reports violations without `BROWSER_UNAVAILABLE`.
4. **Strands Decider 2B & Bedrock Triage**:
   - Expand any violation card.
   - Click **Analyze with AI**.
   - Verify Strands Decider 2B evaluates the `#policy` gate and Amazon Bedrock generates advisory remediation guidance.
