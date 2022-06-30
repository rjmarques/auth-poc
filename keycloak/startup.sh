#!/bin/bash
set -e

# setup initialises keycloak with the desired realm, apps, users, etc.
docker exec -i keycloak sh < ./setup.sh
