port=${1:-10021}
ssh -i image/bullseye.id_rsa -p $port -o "StrictHostKeyChecking no" root@localhost
