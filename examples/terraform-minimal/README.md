# Terraform minimal example

Generic S3 bucket with encryption and public-access block — used by:

- `checkov -d examples/terraform-minimal --framework terraform -o json`
- `hipaa-audit` Checkov integration (`evidence/checkov/`)

Replace `var.bucket_name` and extend for your environment. This is a **pattern reference**, not deployable infrastructure.
