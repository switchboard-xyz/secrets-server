# #choose a name for your VM
# vm_name=$(echo 'demo-vm')

# PUBLIC_IP=$(az vm create --resource-group Default --location uksouth --name $vm_name --image Ubuntu2204 --size Standard_D2s_v3 --admin-username azureuser --generate-ssh-keys --public-ip-sku Standard | grep -oP '(?<="publicIpAddress": ")[^"]*')
# NIC_ID=$(az vm show --resource-group Default --name $vm_name --query 'networkProfile.networkInterfaces[0].id' -o tsv)
# NSG_ID=$(az network nic show --ids $NIC_ID --query 'networkSecurityGroup.id' -o tsv)
# NSG_NAME=$(az network nsg show --ids $NSG_ID --query 'name' -o tsv)

# #expose port 80 to public internet
# az network nsg rule create --resource-group Default --nsg-name $NSG_NAME --name AllowAny80Inbound --priority 1111 --direction Inbound --access Allow --protocol Tcp --destination-port-ranges 80

# echo $PUBLIC_IP

# ssh azureuser@$PUBLIC_IP

# sudo apt update
# sudo apt-get install nginx -y
# sudo service nginx start


#------------------------------

#!/bin/bash

# Set variables
resourceGroup=Default
clusterName=secrets-server
location=uksouth
vmSize=Standard_DC2s_v3
publicIpName=secrets-ip
configFile="secrets-server-values.yaml"

if ! az network public-ip list | jq '.[].name' | grep $publicIpName; then
    echo "Target cluster not found. Creating cluster...";

    # Create a resource group
    az group create --name $resourceGroup --location $location

    # Create an AKS cluster
    az aks create \
        --resource-group $resourceGroup \
        --name $clusterName \
        --node-vm-size $vmSize \
        --generate-ssh-keys

    az network public-ip create \
        --resource-group $resourceGroup \
        --name $publicIpName \
        --allocation-method Static \
        --sku Standard

    # Get the ID of the public IP address
    publicIpId=$(az network public-ip show \
        --resource-group $resourceGroup \
        --name $publicIpName \
        --query id --output tsv)

    publicIpAddress=$(az network public-ip show \
        --resource-group $resourceGroup \
        --name $publicIpName \
        --query ipAddress --output tsv)

    sed -i "s/publicIP:.*$/publicIP: $publicIpAddress/" $configFile

    # Update the AKS cluster to use the public IP address
    az aks update \
        --resource-group $resourceGroup \
        --name $clusterName \
        --load-balancer-managed-outbound-ip-count 0 \
        --load-balancer-outbound-ips $publicIpId

else
    echo "Cluster exists already. Connecting...";
fi

az aks get-credentials --resource-group $resourceGroup --name $clusterName
az aks enable-addons --addons confcom --name $clusterName --resource-group $resourceGroup || true
helm upgrade -i secrets-server ./secrets-server-chart -f $configFile
