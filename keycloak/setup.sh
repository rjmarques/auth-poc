#!/bin/sh
set -e

echo "setting up keyclock PoC"
cd /opt/keycloak/bin

# vars
REALM="longshot"
CLIENT_SECRET_1="my-app1-secret"
CLIENT_SECRET_2="my-app2-secret"
EMPLOYEES_GROUP="employees"
ASSOCIATES_GROUP="associates"

# authenticate as admin
./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin

# add a new realm
echo "adding longshot realm"
./kcadm.sh create realms -s realm=$REALM -s enabled=true -o 

# add new roles
echo "adding realm roles"
./kcadm.sh create roles -r $REALM -s name=booking -s 'description=User that can make bookings'
./kcadm.sh create roles -r $REALM -s name=audit -s 'description=User that can access auditing'
./kcadm.sh create roles -r $REALM -s name=accounts -s 'description=User that can access accounts '

# add new groups
echo "adding new groups"

EMPLOYEES_ID=$(./kcadm.sh create groups -r $REALM -s name=$EMPLOYEES_GROUP -i)
./kcadm.sh add-roles --gid $EMPLOYEES_ID --rolename booking -r $REALM
./kcadm.sh add-roles --gid $EMPLOYEES_ID --rolename audit -r $REALM
./kcadm.sh add-roles --gid $EMPLOYEES_ID --rolename accounts -r $REALM

ASSOCIATES_ID=$(./kcadm.sh create groups -r $REALM -s name=$ASSOCIATES_GROUP -i)
./kcadm.sh add-roles --gid $ASSOCIATES_ID --rolename audit -r $REALM

# add new users and add them to the appropriate group
echo "adding user ric (group $EMPLOYEES_GROUP)"
RIC_ID=$(./kcadm.sh create users -s username=ric -s enabled=true -r $REALM -i)
./kcadm.sh set-password -r $REALM --username ric --new-password ric
./kcadm.sh update users/$RIC_ID/groups/$EMPLOYEES_ID -r $REALM -s realm=$REALM -s userId=$RIC_ID -s groupId=$EMPLOYEES_ID -n
./kcadm.sh remove-roles --uid $RIC_ID --rolename default-roles-longshot -r $REALM 

echo "adding user gary (group $ASSOCIATES_GROUP)"
GARY_ID=$(./kcadm.sh create users -s username=gary -s enabled=true -r $REALM -i)
./kcadm.sh set-password -r $REALM --username gary --new-password gary
./kcadm.sh update users/$GARY_ID/groups/$ASSOCIATES_ID -r $REALM -s realm=$REALM -s userId=$GARY_ID -s groupId=$ASSOCIATES_ID -n
./kcadm.sh remove-roles --uid $GARY_ID --rolename default-roles-longshot -r $REALM 

# add a new client (app)
echo "adding client apps"
./kcadm.sh create clients -r $REALM -s clientId=myapp_1 -s enabled=true -s baseUrl=http://webapp1:8000/ -s clientAuthenticatorType=client-secret -s secret=$CLIENT_SECRET_1 -s standardFlowEnabled=false -s directAccessGrantsEnabled=true -o
./kcadm.sh create clients -r $REALM -s clientId=myapp_2 -s enabled=true -s baseUrl=http://webapp2:9000/ -s clientAuthenticatorType=client-secret -s secret=$CLIENT_SECRET_2 -s standardFlowEnabled=false -s directAccessGrantsEnabled=true -o