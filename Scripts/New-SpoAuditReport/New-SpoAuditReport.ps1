[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $SpoTeanant
)

try {
    # Ensure you have installed the required modules
    # Install-Module -Name Microsoft.Online.SharePoint.Powershell -Force
    # Install-Module -Name PnP.PowerShell -Force

    # Import the required modules
    Import-Module Microsoft.Online.SharePoint.Powershell
    Import-Module PnP.PowerShell

    # Define your SharePoint Online admin URL and credentials
    $adminSiteUrl = "https://yourtenant-admin.sharepoint.com"
    $username = "yourusername@yourtenant.onmicrosoft.com"
    $password = "yourpassword"

    # Convert to a secure string
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    # Create a PSCredential object
    $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

    # Connect to SharePoint Online
    Connect-SPOService -Url $adminSiteUrl -Credential $credential

    # Connect to PnP Online
    Connect-PnPOnline -Url $adminSiteUrl -Credentials $credential

    # Get all site collections
    $siteCollections = Get-SPOSite -Limit All

    # Create a list to hold the report data
    $report = @()

    foreach ($site in $siteCollections) {
        # Connect to each site collection
        Connect-PnPOnline -Url $site.Url -Credentials $credential

        # Get site details
        $siteDetails = Get-PnPTenantSite -Detailed -Url $site.Url

        # Get site owner information
        $siteOwner = Get-SPOUser -Site $site.Url -LoginName $site.Owner

        if ($siteOwner.PrincipalType -eq "SecurityGroup") {
            # If the owner is a group, get group members
            $groupMembers = Get-PnPGroupMembers -Identity $siteOwner.Title
            $siteOwnerInfo = $groupMembers | ForEach-Object { $_.Email }
        } else {
            $siteOwnerInfo = $siteOwner.Email
        }

        # Get site usage details
        $siteUsage = Get-PnPTenantSiteUsageDetail -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) | Where-Object { $_.SiteUrl -eq $site.Url }

        # Get root page last modified date
        $rootPage = Get-PnPFile -Url "$($site.Url)/SitePages/Home.aspx" -AsListItem
        $rootPageLastModified = $rootPage["Modified"]

        # Calculate site quota percentage used
        $siteQuotaPercentageUsed = [math]::Round(($siteDetails.StorageUsageCurrent / $siteDetails.StorageQuota) * 100, 2)

        # Create a custom object for the report
        $reportItem = [PSCustomObject]@{
            SiteName                = $siteDetails.Title
            SiteUrl                 = $site.Url
            SiteOwner               = $siteOwnerInfo -join ", "
            RootPageLastModified    = $rootPageLastModified
            QuotaLimitMB            = $siteDetails.StorageQuota / 1MB
            TotalStorageUsedMB      = $siteDetails.StorageUsageCurrent / 1MB
            SiteQuotaPercentageUsed = $siteQuotaPercentageUsed
            ViewsLast30Days         = $siteUsage.ViewsLifeTime
            FileActionsLast30Days   = $siteUsage.FileModifiedCount
        }

        # Add the report item to the report list
        $report += $reportItem
    }

    # Export the report to a CSV file
    $report | Export-Csv -Path "SharePointOnlineAuditReport.csv" -NoTypeInformation

    # Disconnect from SharePoint Online
    Disconnect-PnPOnline
    Disconnect-SPOService

    Write-Host "Audit report generated successfully."
}
catch {
    <#Do this if a terminating exception happens#>
}