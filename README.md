# infrastructure

aws cloudformation create-stack \
  --stack-name csye6225demo \
  --parameters file://param.json  \
  --template-body file://networking.json




sudo aws acm import-certificate --certificate fileb://certificate.pem --certificate-chain fileb://certificate_chain.pem --private-key fileb://prodswetachowdhuryssl.key --profile prod