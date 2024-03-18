# DataOps-aws
The purpose of this project is develop an ETL application on AWS using DataOps knowledge. DataOps, short for Data Operations, is an approach that emphasizes collaboration and communication between data engineers, data scientist, and other data-related proffesionals. The goal of DataOps is to improve the overall efficiency and effectiveness of data-related processes throughout the entire data lifecycle.

## The advantages of DataOps:

1. **Collaboration:**
    - Cross-functional Teams
    - Communication
2. **Agile Methodologies:**
3. **Automation:**
    - Workflow Automation:
    - Infrastructure as Code (IaC)
4. **Version Control:**
5. **Monitoring and Logging:**
    - Operational Monitoring
    - Alerts and Notifications
6. **DevOps Practices:**
    - Infrastructure as Code (IaC)
    - Continuous Integration/Continuous Deployment (CI/CD)
7. **Quality and Testing:**
    - Data Quality Management
    - Automated Testing

## List of tools we'll be using

### CI/CD (Github Workflow)

- `verify.yml` for testing and validation of resource construction
- `deploy.yml` for building resources
- `destroy.yml` for resource destruction

### GitOps

- ArgoCD

### **Resource Construction**

- Terraform

---

### AWS Tools

- Lambda Function
- RDS
- Redshift
- Athena
- S3
- EMR
- Glue Crawler
- Glue Database
- Policy
- Roles
- EKS
- VPC
- SNS
- Security Groups

---

### **Pipeline Orchestration**

- Airflow (*Helm Chart used:* https://artifacthub.io/packages/helm/airflow-helm/airflow)
