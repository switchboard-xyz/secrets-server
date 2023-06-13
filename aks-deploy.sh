#!/bin/bash
set -e
clusterName=secrets-server3
publicIpName=secrets-ip3
resourceGroup=Default
location=uksouth
vmSize=Standard_DC2s_v3
configFile="secrets-server-values.yaml"
publicIpAddress=""

if ! az aks list | jq '.[].name' | grep $clusterName > /dev/null; then
    echo "Target cluster not found. Creating cluster...";

    # Create a resource group
    az group create --name $resourceGroup --location $location

    # Create an AKS cluster
    az aks create \
        --resource-group $resourceGroup \
        --name $clusterName \
        --node-vm-size $vmSize \
        --generate-ssh-keys

    nodeResourceGroup=$(az aks show --resource-group $resourceGroup --name $clusterName --query nodeResourceGroup -o tsv)

    az network public-ip create \
        --resource-group $nodeResourceGroup \
        --name $publicIpName \
        --allocation-method Static \
        --sku Standard

    # Get the ID of the public IP address
    publicIpId=$(az network public-ip show \
        --resource-group $nodeResourceGroup \
        --name $publicIpName \
        --query id --output tsv)

    publicIpAddress=$(az network public-ip show \
        --resource-group $nodeResourceGroup \
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

nodeResourceGroup=$(az aks show --resource-group $resourceGroup --name $clusterName --query nodeResourceGroup -o tsv)
publicIpId=$(az network public-ip show \
    --resource-group $nodeResourceGroup \
    --name $publicIpName \
    --query id --output tsv)
publicIpAddress=$(az network public-ip show \
    --resource-group $nodeResourceGroup \
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
