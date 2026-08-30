# Deploying heiLLMpot with OpenTofu

## 1. Setup AWS Credentials
1. Create an AWS IAM User with `AmazonEC2FullAccess`.
2. Generate an Access Key.
3. Add the keys to the `.env` file at the root of the repository:
   ```env
   AWS_ACCESS_KEY_ID="AKIA..."
   AWS_SECRET_ACCESS_KEY="..."
   ```

## 2. Deploy
Run the following commands to configure and deploy the infrastructure:

```bash
cd deploy/environments/aws

cp config.json.example config.json

set -a && source ../../../.env && set +a
tofu init

tofu apply
```

OpenTofu will automatically generate SSH keys and output the exact connection commands (with full paths) for all instances when finished.

## 3. Teardown
To destroy all instances and stop incurring costs:
```bash
cd deploy/environments/aws
set -a && source ../../../.env && set +a
tofu destroy
```
