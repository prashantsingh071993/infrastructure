# infrastructure

aws cloudformation create-stack \
  --stack-name csye6225demo \
  --parameters file://param.json  \
  --template-body file://networking.json