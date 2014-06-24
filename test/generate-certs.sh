#!/bin/bash

#echo "../ev-checker -c github.com.pem -o 2.16.840.1.114412.2.1 -d 'DigiCert'" > run-tests.sh
echo "#!/bin/bash" > run-tests.sh
chmod u+x run-tests.sh
openssl req -new -x509 -days 1825 -nodes -out CA.pem -config ev-ca.cnf
openssl req -new -days 365 -nodes -out int.req -config ev-int.cnf
openssl x509 -req -in int.req -CA CA.pem -CAkey CA.key -extensions v3_int -out int.pem -set_serial 1 -extfile ev-int.cnf
#openssl req -new -out non-ev-cert.req -days 365 -nodes
#openssl x509 -req -in non-ev-cert.req -CA int.pem -CAkey int.key -extensions usr_cert -out non-ev-cert.pem -set_serial 1
#cat CA.pem int.pem non-ev-cert.pem > non-ev-chain.pem
openssl req -new -out ev-cert.req -days 365 -nodes -config ev.cnf
openssl x509 -req -in ev-cert.req -CA int.pem -CAkey int.key -out ev-cert.pem -extfile ev.cnf -set_serial 2 -extensions v3_req
cat ev-cert.pem int.pem CA.pem > ev-chain.pem
echo "../ev-checker -c ev-chain.pem -o 1.3.6.1.4.1.13769.666.666.666.1.500.9.1 -d 'Test EV Policy'" >> run-tests.sh
#openssl req -new -out ev-cert-no-int.req -days 365 config ev.cnf
#openssl x509 -req -in ev-cert-no-int.req -CA CA.pem -CAkey CA.key -out ev-cert-no-int.pem -extfile ev.cnf -set_serial 2 -extensions v3_req
#cat CA.pem ev-cert-no-int.pem > ev-chain-no-int.pem
