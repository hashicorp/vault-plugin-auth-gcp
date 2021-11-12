#!/usr/bin/env bats

#load _helpers
#
#SKIP_TEARDOWN=true
VAULT_ADDR='http://127.0.0.1:8200'
VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.9.0-rc1}"

if [[ -z SERVICE_ACCOUNT_ID ]]
then
    echo "SERVICE_ACCOUNT_ID env is not set. Exiting.."
    exit 1
fi

if [[ -z PATH_TO_CREDS ]]
then
    echo "PATH_TO_CREDS env is not set. Exiting.."
    exit 1
fi

export SETUP_TEARDOWN_OUTFILE=/tmp/output.log

setup(){
    { # Braces used to redirect all setup logs.
    # 1. Configure Vault.
    VAULT_TOKEN='root'
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

    docker pull ${VAULT_IMAGE?}

    docker run \
      --name=vault \
      --hostname=vault \
      -p 8200:8200 \
      -e VAULT_DEV_ROOT_TOKEN_ID="root" \
      -e VAULT_ADDR="http://localhost:8200" \
      -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
      --privileged \
      --detach ${VAULT_IMAGE?}

    # Replace with a check
    sleep 2

    vault login ${VAULT_TOKEN?}

    vault auth enable gcp
    } >> $SETUP_TEARDOWN_OUTFILE
}

teardown(){
    if [[ -n $SKIP_TEARDOWN ]]; then
        echo "Skipping teardown"
        return
    fi

    { # Braces used to redirect all teardown logs.

    vault auth disable gcp
    # If the test failed, print some debug output
    if [[ "$BATS_ERROR_STATUS" -ne 0 ]]; then
        docker logs vault
    fi

    # Teardown Vault configuration.
    docker rm vault --force
    } >> $SETUP_TEARDOWN_OUTFILE
}

@test "Can successfuly write GCP Auth Config" {
    run vault write auth/gcp/config \
          credentials="@${PATH_TO_CREDS?}"
    [ "${status?}" -eq 0 ]
}

@test "Can successfully write IAM role" {
    run vault write auth/gcp/role/my-iam-role \
          type="iam" \
          policies="dev,prod" \
          bound_service_accounts=${SERVICE_ACCOUNT_ID?}
    [ "${status?}" -eq 0 ]
}

@test "Can successfully write GCE role" {
    run vault write auth/gcp/role/my-gce-role \
          type="gce" \
          policies="dev,prod" \
          bound_service_accounts=${SERVICE_ACCOUNT_ID?}
    [ "${status?}" -eq 0 ]
}

@test "Can successfully login using IAM role" {
   run vault write auth/gcp/config \
          credentials="@${PATH_TO_CREDS?}"

   run vault write auth/gcp/role/my-iam-role \
          type="iam" \
          policies="dev,prod" \
          bound_service_accounts=${SERVICE_ACCOUNT_ID?}

   run vault login -method=gcp \
          role="my-iam-role" \
          service_account=${SERVICE_ACCOUNT_ID?} \
          jwt_exp="15m" \
          credentials="@${PATH_TO_CREDS?}"

   [ "${status?}" -eq 0 ]
} >> $SETUP_TEARDOWN_OUTFILE
