# Define the SharePoint site URL
$siteUrl = "https://yourtenant.sharepoint.com/sites/yoursite"

# Get the site ID
$site = Get-MgSite -SiteId $siteUrl

# Get the site's group ID (if it's a Group-connected site)
$group = Get-MgGroup -Filter "resourceProvisioningOptions/Any(x:x eq 'TeamSite')" -Search $site.DisplayName

if ($group) {
    # Get the owners of the group
    $owners = Get-MgGroupOwner -GroupId $group.Id

    # Display the owners
    $owners | ForEach-Object {
        Write-Output $_.UserPrincipalName
    }
} else {
    Write-Output "The site is not connected to a Microsoft 365 group or could not be found."
}