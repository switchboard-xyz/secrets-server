#!/bin/bash
set -e
resourceGroup=Default
clusterName=secrets-server
location=uksouth
vmSize=Standard_DC2s_v3
publicIpName=secrets-ip
configFile="secrets-server-values.yaml"
publicIpAddress=""

if ! az network public-ip list | jq '.[].name' | grep $publicIpName > /dev/null; then
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

    sed -iE "s;publicIP.*$;publicIP: $publicIpAddress;" $configFile

    # Update the AKS cluster to use the public IP address
    az aks update \
        --resource-group $resourceGroup \
        --name $clusterName \
        --load-balancer-managed-outbound-ip-count 0 \
        --load-balancer-outbound-ips $publicIpId

else
    echo "Cluster exists already. Connecting...";
fi

publicIpId=$(az network public-ip show \
    --resource-group $resourceGroup \
    --name $publicIpName \
    --query id --output tsv)
publicIpAddress=$(az network public-ip show \
    --resource-group $resourceGroup \
    --name $publicIpName \
    --query ipAddress --output tsv)
sed -i "s/publicIP:.*$/publicIP: $publicIpAddress/" $configFile
CLIENT_ID=$(az aks show --name $clusterName --resource-group $resourceGroup --query identity.principalId -o tsv)
RG_SCOPE=$(az group show --name $resourceGroup --query id -o tsv)
az role assignment create \
    --assignee ${CLIENT_ID} \
    --role "Network Contributor" \
    --scope ${RG_SCOPE}
az aks get-credentials --resource-group $resourceGroup --name $clusterName
az aks enable-addons --addons confcom --name $clusterName --resource-group $resourceGroup 2> /dev/null || true
helm upgrade -i secrets-server ./secrets-server-chart -f $configFile
echo -e "\033[0;32mServer hosted at $publicIpAddress\033[0m"
