# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Source this script from your shell:
#
# . scripts/cred_setup.sh


# Enable the IAM service on the project:
gcloud services enable --project "${GOOGLE_CLOUD_PROJECT}" \
        cloudresourcemanager.googleapis.com \
        iam.googleapis.com

# Create the service account:
gcloud iam service-accounts create vault-tester \
        --display-name vault-tester \
        --project "${GOOGLE_CLOUD_PROJECT}"

# Grant `project.viewer` and `serviceaccount.admin` permissions:
gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
        --member "serviceAccount:vault-tester@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
        --role "roles/viewer"

gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
       --member "serviceAccount:vault-tester@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
        --role "roles/iam.serviceAccountKeyAdmin"

gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
        --member "serviceAccount:vault-tester@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
        --role "roles/iam.serviceAccountTokenCreator"

# Download the service account key file to local disk:
gcloud iam service-accounts keys create vault-tester.json \
        --iam-account "vault-tester@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"

export GOOGLE_CREDENTIALS="$(cat vault-tester.json)"
printf "\nUpdated the GOOGLE_CREDENTIALS environment variable."

printf "\n\nYou may now run 'make test', but note that it may take some time (e.g. over a minute) for the new credentials to work.\n"
