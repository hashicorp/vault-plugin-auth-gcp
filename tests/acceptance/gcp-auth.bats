#!/usr/bin/env bats

#load _helpers
#
#SKIP_TEARDOWN=true
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.9.1}"

if [[ -z $SERVICE_ACCOUNT_ID ]]
then
    echo "SERVICE_ACCOUNT_ID env is not set. Exiting.."
    exit 1
fi

if [[ -z $GOOGLE_APPLICATION_CREDENTIALS ]]
then
    echo "GOOGLE_APPLICATION_CREDENTIALS env is not set. Exiting.."
    exit 1
fi

export SETUP_TEARDOWN_OUTFILE=/tmp/output.log

setup(){
    { # Braces used to redirect all setup logs.
    # 1. Copy credentials file
    cp $GOOGLE_APPLICATION_CREDENTIALS ./creds.json

    # 2. Configure Vault.
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

    echo -n "waiting for vault"
    while ! vault status >/dev/null 2>&1; do sleep 1; echo -n .; done; echo

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

    # Remove temp credentials file
    rm ./creds.json

    vault auth disable gcp
    # If the test failed, print some debug output
    if [[ "$BATS_ERROR_STATUS" -ne 0 ]]; then
        docker logs vault
    fi

    # Teardown Vault configuration.
    docker rm vault --force
    } >> $SETUP_TEARDOWN_OUTFILE
}

@test "Can successfully write GCP Auth Config" {
    run vault write auth/gcp/config \
          credentials="@creds.json"
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
    vault write auth/gcp/config \
          credentials="@creds.json"

    vault write auth/gcp/role/my-iam-role \
          type="iam" \
          policies="dev,prod" \
          bound_service_accounts=${SERVICE_ACCOUNT_ID?}

    run vault login -method=gcp \
          role="my-iam-role" \
          service_account=${SERVICE_ACCOUNT_ID?} \
          jwt_exp="15m" \
          credentials="@creds.json"

   [ "${status?}" -eq 0 ]
}
