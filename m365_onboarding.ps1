<#
.SYNOPSIS
  Microsoft 365 Onboarding Script for Vulneri FinOps M365.
  
.DESCRIPTION
  This script automates the onboarding process of a Microsoft 365 tenant for Vulneri FinOps:
  - Creates or updates an Entra ID App Registration & Service Principal
  - Configures RequiredResourceAccess for either "Starter" or "Expert" permissions
  - Generates a client secret with custom expiration
  - Generates the Admin Consent URL
  - Performs validation checks on an existing client configuration
  - Renews client secrets

.EXAMPLE
  pwsh ./m365_onboarding.ps1 -Mode Starter
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "Vulneri FinOps M365",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Starter","Expert")]
    [string]$Mode = "Starter",

    [Parameter(Mandatory = $false)]
    [int]$SecretMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

    [Parameter(Mandatory = $false)]
    [switch]$RenewSecret,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [switch]$WriteEnvFile
)

# ==========================================
# 1. LOGGING FUNCTIONS (English Console Logs)
# ==========================================

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ==========================================
# 2. PARAMETER VALIDATION
# ==========================================

if ($ValidateOnly -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "The -ClientId parameter is required when -ValidateOnly is used."
    exit 1
}

if ($RenewSecret -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "The -ClientId parameter is required when -RenewSecret is used."
    exit 1
}

# ==========================================
# 3. MODULE AND CONNECTION FUNCTIONS
# ==========================================

function Ensure-GraphModule {
    Write-Info "Verifying PowerShell dependencies..."
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
    )

    foreach ($module in $requiredModules) {
        Write-Info "Checking $module..."
        $installed = Get-Module -ListAvailable -Name $module
        if (-not $installed) {
            Write-Info "Installing $module..."
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Info "$module installed successfully."
            }
            catch {
                Write-Err "Failed to install $module - $($_.Exception.Message)"
                Write-Err "Please run: Install-Module $module -Scope CurrentUser -Force -AllowClobber"
                exit 1
            }
        }

        Write-Info "Loading $module..."
        try {
            Import-Module $module -ErrorAction Stop
            Write-Info "$module loaded."
        }
        catch {
            Write-Err "Failed to load $module - $($_.Exception.Message)"
            exit 1
        }
    }

    # Validate required cmdlets
    $requiredCmdlets = @(
        "Connect-MgGraph",
        "Get-MgContext",
        "Get-MgApplication",
        "New-MgApplication",
        "Update-MgApplication",
        "Add-MgApplicationPassword",
        "Get-MgServicePrincipal",
        "New-MgServicePrincipal",
        "Get-MgServicePrincipalAppRoleAssignment"
    )

    Write-Info "Verifying required cmdlets..."
    $missingCmdlets = @()
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) {
            $missingCmdlets += $cmdlet
        }
    }

    if ($missingCmdlets.Count -gt 0) {
        Write-Err "The following required cmdlets are missing: $($missingCmdlets -join ', ')"
        Write-Err "Please reinstall the Graph modules by running the following commands:"
        Write-Err "  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber"
        Write-Err "  Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber"
        exit 1
    }
    Write-Info "All required cmdlets verified successfully."
}

function Connect-GraphForOnboarding {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    $scopes = @("Application.ReadWrite.All", "Directory.Read.All")
    Write-Info "Connecting to Microsoft Graph with required delegated scopes..."
    
    $connectParams = @{
        Scopes = $scopes
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrEmpty($TenantId)) {
        $connectParams["TenantId"] = $TenantId
    }
    
    Connect-MgGraph @connectParams | Out-Null
    
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Could not retrieve TenantId from the active Microsoft Graph context."
    }
    return $ctx.TenantId
}

# ==========================================
# 4. PERMISSIONS & ROLES RESOLUTION
# ==========================================

function Get-PermissionsForMode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    $starterPerms = @(
        "Directory.Read.All",
        "LicenseAssignment.Read.All",
        "Reports.Read.All",
        "MailboxSettings.Read",
        "ReportSettings.Read.All"
    )
    
    if ($Mode -eq "Expert") {
        $expertPerms = $starterPerms + @(
            "Policy.Read.All",
            "SecurityEvents.Read.All",
            "Application.Read.All",
            "AuditLog.Read.All",
            "RoleManagement.Read.Directory",
            "IdentityRiskyUser.Read.All"
        )
        return $expertPerms
    }
    
    return $starterPerms
}

function Get-GraphServicePrincipal {
    $graphAppId = "00000003-0000-0000-c000-000000000000"
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    if (-not $graphSp) {
        throw "Could not locate the Microsoft Graph Service Principal."
    }
    return $graphSp
}

function Resolve-GraphAppRoles {
    param(
        [Parameter(Mandatory = $true)]
        $GraphSp,
        [Parameter(Mandatory = $true)]
        [string[]]$Permissions
    )
    $appRoleMap = @{}
    foreach ($val in $Permissions) {
        $role = $GraphSp.AppRoles | Where-Object {
            $_.Value -eq $val -and $_.AllowedMemberTypes -contains "Application"
        }
        if (-not $role) {
            throw "The permission (AppRole) '$val' was not found in the Microsoft Graph Service Principal."
        }
        $appRoleMap[$val] = $role.Id
    }
    return $appRoleMap
}

# ==========================================
# 5. APP REGISTRATION MANAGEMENT
# ==========================================

function New-VulneriM365Application {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,
        [Parameter(Mandatory = $true)]
        [hashtable]$AppRoleMap,
        [Parameter(Mandatory = $true)]
        [string[]]$Permissions
    )
    $graphAppId = "00000003-0000-0000-c000-000000000000"
    
    Write-Info "Checking if an App Registration named '$DisplayName' already exists..."
    $existingApps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    $app = $null
    if ($existingApps) {
        Write-Warn "An App Registration with the name '$DisplayName' already exists in your tenant."
        
        $choice = ""
        if ([Environment]::UserInteractive) {
            Write-Host "Do you want to reuse the existing App Registration? (Y/N): " -NoNewline
            $choice = Read-Host
        } else {
            Write-Warn "Non-interactive execution detected. Reusing the existing App Registration by default."
            $choice = "Y"
        }
        
        if ($choice -match "^[yYsS]") {
            $app = $existingApps[0]
            Write-Info "Reusing existing App Registration. Application ID (ClientId): $($app.AppId)"
        } else {
            Write-Info "Creating a new App Registration with the same name..."
        }
    }
    
    $resourceAccess = @()
    foreach ($val in $Permissions) {
        $resourceAccess += @{
            Id   = $AppRoleMap[$val]
            Type = "Role"
        }
    }
    
    $requiredResourceAccess = @(
        @{
            ResourceAppId  = $graphAppId
            ResourceAccess = $resourceAccess
        }
    )
    
    if ($app) {
        Write-Info "Updating configured permissions on the App Registration..."
        $updateParams = @{
            RequiredResourceAccess = $requiredResourceAccess
        }
        Update-MgApplication -ApplicationId $app.Id @updateParams -ErrorAction Stop
        # Fetch the updated app object to return
        $app = Get-MgApplication -ApplicationId $app.Id -ErrorAction Stop
    } else {
        Write-Info "Creating a new App Registration..."
        $appParams = @{
            DisplayName            = $DisplayName
            SignInAudience         = "AzureADMyOrg"
            RequiredResourceAccess = $requiredResourceAccess
            Web                    = @{
                RedirectUris = @("https://localhost")
            }
        }
        $app = New-MgApplication @appParams -ErrorAction Stop
        Write-Info "App Registration created successfully."
    }
    
    Write-Info "Ensuring corresponding Service Principal exists..."
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Info "Creating Service Principal..."
        $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        Write-Info "Service Principal created successfully."
    } else {
        Write-Info "Service Principal already exists."
    }
    
    return [pscustomobject]@{
        Application      = $app
        ServicePrincipal = $sp
    }
}

function New-VulneriM365Secret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)]
        [int]$SecretMonths
    )
    Write-Info "Adding a new client secret..."
    $secretDisplayName = "vulneri-finops-secret"
    $endDate = (Get-Date).AddMonths($SecretMonths)
    
    $passwordCred = @{
        displayName  = $secretDisplayName
        endDateTime  = $endDate.ToUniversalTime()
    }
    
    $secretObj = Add-MgApplicationPassword -ApplicationId $ApplicationObjectId -PasswordCredential $passwordCred -ErrorAction Stop
    $clientSecret = $secretObj.SecretText
    
    if (-not $clientSecret) {
        throw "Failed to generate Client Secret (empty return value)."
    }
    
    return [pscustomobject]@{
        SecretText  = $clientSecret
        DisplayName = $secretDisplayName
        ExpiresAt   = $endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

function Get-AdminConsentUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId
    )
    $redirectUri = [System.Net.WebUtility]::UrlEncode("https://localhost")
    $scope = [System.Net.WebUtility]::UrlEncode("https://graph.microsoft.com/.default")
    $adminConsentUrl = "https://login.microsoftonline.com/$TenantId/v2.0/adminconsent?client_id=$ClientId&scope=$scope&redirect_uri=$redirectUri"
    return $adminConsentUrl
}

# ==========================================
# 6. VALIDATION AND RENEWAL
# ==========================================

function Test-VulneriM365Onboarding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    Write-Info "Starting App Registration validation for ClientId: $ClientId..."
    
    $permissionsExpected = Get-PermissionsForMode -Mode $Mode
    $checkedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    try {
        # Find application
        Write-Info "Locating App Registration..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration with ClientId '$ClientId' was not found."
        }
        
        # Find Service Principal
        Write-Info "Locating Service Principal..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $sp) {
            throw "Corresponding Service Principal for ClientId '$ClientId' was not found."
        }
        
        # Get Graph SP
        $graphSp = Get-GraphServicePrincipal
        $graphAppId = "00000003-0000-0000-c000-000000000000"
        
        # Build maps
        $idToNameMap = @{}
        foreach ($role in $graphSp.AppRoles) {
            $idToNameMap[$role.Id.ToString()] = $role.Value
        }
        
        # Get configured permissions
        $permissionsConfigured = @()
        if ($app.RequiredResourceAccess) {
            $graphAccess = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $graphAppId }
            if ($graphAccess -and $graphAccess.ResourceAccess) {
                foreach ($acc in $graphAccess.ResourceAccess) {
                    $roleId = $acc.Id.ToString()
                    if ($idToNameMap.ContainsKey($roleId)) {
                        $permissionsConfigured += $idToNameMap[$roleId]
                    } else {
                        $permissionsConfigured += $roleId
                    }
                }
            }
        }
        
        # Get granted permissions
        $permissionsGranted = @()
        Write-Info "Fetching permissions with admin consent..."
        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
        if ($assignments) {
            $graphAssignments = $assignments | Where-Object { $_.ResourceId -eq $graphSp.Id }
            foreach ($asg in $graphAssignments) {
                $roleId = $asg.AppRoleId.ToString()
                if ($idToNameMap.ContainsKey($roleId)) {
                    $permissionsGranted += $idToNameMap[$roleId]
                } else {
                    $permissionsGranted += $roleId
                }
            }
        }
        
        # Calculate missing and pending
        $permissionsMissing = @()
        foreach ($expected in $permissionsExpected) {
            if ($expected -notin $permissionsConfigured) {
                $permissionsMissing += $expected
            }
        }
        
        $permissionsPendingConsent = @()
        foreach ($expected in $permissionsExpected) {
            if ($expected -in $permissionsConfigured -and $expected -notin $permissionsGranted) {
                $permissionsPendingConsent += $expected
            }
        }
        
        # Validation status
        $validationStatus = "ready"
        if ($permissionsMissing.Count -gt 0) {
            $validationStatus = "missing_permissions"
            Write-Warn "Validation: Some expected permissions are not configured in RequiredResourceAccess."
        }
        elseif ($permissionsPendingConsent.Count -gt 0) {
            $validationStatus = "pending_admin_consent"
            Write-Warn "Validation: Configured permissions are pending administrator consent."
        }
        else {
            Write-Info "Validation: All set! All required permissions have been configured and consented."
        }
        
        $output = @{
            provider                   = "m365"
            mode                       = $Mode.ToLower()
            m365TenantId               = $TenantId
            m365ClientId               = $ClientId
            validationStatus           = $validationStatus
            permissionsExpected        = $permissionsExpected
            permissionsConfigured      = $permissionsConfigured
            permissionsMissing         = $permissionsMissing
            permissionsGranted         = $permissionsGranted
            permissionsPendingConsent  = $permissionsPendingConsent
            checkedAt                  = $checkedAt
        }
        
        return $output
    }
    catch {
        Write-Err "Error during validation: $($_.Exception.Message)"
        return @{
            provider                   = "m365"
            mode                       = $Mode.ToLower()
            m365TenantId               = $TenantId
            m365ClientId               = $ClientId
            validationStatus           = "error"
            errorMessage               = $_.Exception.Message
            permissionsExpected        = $permissionsExpected
            permissionsConfigured      = @()
            permissionsMissing         = $permissionsExpected
            permissionsGranted         = @()
            permissionsPendingConsent  = @()
            checkedAt                  = $checkedAt
        }
    }
}

function Renew-VulneriM365Secret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [int]$SecretMonths
    )
    Write-Info "Starting Client Secret renewal for ClientId: $ClientId..."
    
    try {
        Write-Info "Locating the App Registration in the tenant..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration with ClientId '$ClientId' was not found."
        }
        
        $secret = New-VulneriM365Secret -ApplicationObjectId $app.Id -SecretMonths $SecretMonths
        $renewedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $output = @{
            provider            = "m365"
            m365TenantId        = $TenantId
            m365ClientId        = $ClientId
            m365ClientSecret    = $secret.SecretText
            secretDisplayName   = $secret.DisplayName
            secretExpiresAt     = $secret.ExpiresAt
            renewedAt           = $renewedAt
            onboardingStatus    = "secret_renewed"
        }
        
        return $output
    }
    catch {
        Write-Err "Error renewing secret: $($_.Exception.Message)"
        exit 1
    }
}

# ==========================================
# 7. OUTPUT MANAGEMENT
# ==========================================

function ConvertTo-SafeJsonOutput {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Payload
    )
    return $Payload | ConvertTo-Json -Depth 5 -Compress
}

function Write-OptionalEnvFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $false)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $false)]
        [string]$SecretExpiresAt,
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    $envPath = Join-Path -Path (Get-Location) -ChildPath ".env"
    
    if (Test-Path $envPath) {
        Write-Warn "The '.env' file already exists in the current directory and will be overwritten."
    }
    
    $lines = @(
        "M365_TENANT_ID=$TenantId",
        "M365_CLIENT_ID=$ClientId"
    )
    if (-not [string]::IsNullOrEmpty($ClientSecret)) {
        $lines += "M365_CLIENT_SECRET=$ClientSecret"
    }
    if (-not [string]::IsNullOrEmpty($SecretExpiresAt)) {
        $lines += "M365_SECRET_EXPIRES_AT=$SecretExpiresAt"
    }
    $lines += "M365_ONBOARDING_MODE=$($Mode.ToLower())"
    
    $lines | Out-File -FilePath $envPath -Encoding ascii -Force
    
    Write-Warn "============================================================"
    Write-Warn "SECURITY WARNING: .env file generated at: $envPath"
    Write-Warn "Use -WriteEnvFile for testing or controlled environments only."
    Write-Warn "This file contains highly sensitive credentials."
    Write-Warn "Never commit this file to Git repositories or share it."
    Write-Warn "============================================================"
}

# ==========================================
# 8. CORE EXECUTION LOGIC
# ==========================================

try {
    Write-Host "== Vulneri Microsoft 365 Onboarding ==" -ForegroundColor Cyan
    Write-Info "This script only configures Microsoft 365 access. The scanner will run on the Vulneri backend."
    Write-Info "Local machine administrator privileges are not required; tenant administrator privileges may be needed."
    
    if ($ValidateOnly) {
        Write-Info "Selected mode: Permission Validation (-ValidateOnly)"
    } elseif ($RenewSecret) {
        Write-Info "Selected mode: Credential Renewal (-RenewSecret)"
    } else {
        Write-Info "Selected mode: $Mode"
        if ($Mode -eq "Starter") {
            Write-Info "This mode requests only read-only permissions for license inventory and usage."
        } else {
            Write-Info "This mode requests additional permissions for security, governance, identity, and applications."
        }
    }
    Write-Host ""
    
    # Check dependencies and module
    Ensure-GraphModule
    
    # Establish connection and infer or validate TenantId
    $activeTenantId = Connect-GraphForOnboarding -TenantId $TenantId
    
    if ($ValidateOnly) {
        # Perform validation
        $valOutput = Test-VulneriM365Onboarding -TenantId $activeTenantId -ClientId $ClientId -Mode $Mode
        
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "VALIDATION RESULT (JSON):" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $valOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $ClientId -Mode $Mode
        }
    }
    elseif ($RenewSecret) {
        # Perform secret renewal
        $renewOutput = Renew-VulneriM365Secret -TenantId $activeTenantId -ClientId $ClientId -SecretMonths $SecretMonths
        
        Write-Host ""
        Write-Warn "Recommendation: Remove old secrets in the Azure/Entra console only after validating the new credential on the Vulneri platform."
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "COPY AND PASTE THE JSON BELOW INTO THE VULNERI PLATFORM:" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $renewOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $ClientId -ClientSecret $renewOutput.m365ClientSecret -SecretExpiresAt $renewOutput.secretExpiresAt -Mode $Mode
        }
    }
    else {
        # Creation flow
        $permissions = Get-PermissionsForMode -Mode $Mode
        
        Write-Info "Locating Service Principal do Microsoft Graph..."
        $graphSp = Get-GraphServicePrincipal
        $appRoleMap = Resolve-GraphAppRoles -GraphSp $graphSp -Permissions $permissions
        
        $appResult = New-VulneriM365Application -DisplayName $DisplayName -AppRoleMap $appRoleMap -Permissions $permissions
        $app = $appResult.Application
        
        # Create client secret, but DO NOT print it yet!
        $secretResult = New-VulneriM365Secret -ApplicationObjectId $app.Id -SecretMonths $SecretMonths
        $consentUrl = Get-AdminConsentUrl -TenantId $activeTenantId -ClientId $app.AppId
        
        # Interactive Admin Consent validation loop
        $validated = $false
        while (-not $validated) {
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host "ACTION REQUIRED: GRANT ADMINISTRATOR CONSENT" -ForegroundColor Yellow
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host "The App Registration has been created in the customer's Microsoft 365 tenant,"
            Write-Host "but is NOT yet authorized to read the data."
            Write-Host ""
            Write-Host "Before registering credentials on the Vulneri platform, a tenant administrator"
            Write-Host "needs to grant consent for the requested permissions."
            Write-Host ""
            Write-Host "Who can do this:"
            Write-Host "- Global Administrator"
            Write-Host "- Privileged Role Administrator"
            Write-Host "- or equivalent role with permissions to grant admin consent"
            Write-Host ""
            Write-Host "The Vulneri scanner will NOT be able to run until this consent"
            Write-Host "is granted."
            Write-Host ""
            Write-Host "Open the URL below in your browser, review the permissions, and click Accept."
            Write-Host "Then return to this terminal and press ENTER to validate."
            Write-Host ""
            Write-Host "Important:"
            Write-Host "The secret was created, but will only be displayed after consent"
            Write-Host "is successfully validated. If this terminal is closed before then,"
            Write-Host "you will need to generate a new secret using -RenewSecret."
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Admin Consent URL:" -ForegroundColor Yellow
            Write-Host "  $consentUrl" -ForegroundColor Cyan
            Write-Host ""
            
            # Browser auto-opening logic (if local and safe)
            $isCloudShell = $env:AZURE_HTTP_USER_AGENT -like "*cloud-shell*" -or $env:ACC_TERM_ID
            if (-not $isCloudShell) {
                try {
                    Write-Info "Attempting to open the URL in your browser automatically..."
                    if ($IsWindows) {
                        Start-Process $consentUrl
                    } elseif ($IsMacOS) {
                        Start-Process "open" $consentUrl
                    } elseif ($IsLinux) {
                        Start-Process "xdg-open" $consentUrl
                    } else {
                        # Fallback for compatibility with older PowerShell hosts
                        Start-Process $consentUrl
                    }
                }
                catch {
                    Write-Warn "Could not open the browser automatically: $($_.Exception.Message)"
                    Write-Warn "Please copy and paste the URL above manually into your browser."
                }
            } else {
                Write-Info "Running in Azure Cloud Shell. Please copy and paste the URL above manually into your browser."
            }
            
            Write-Host ""
            Write-Host "Press ENTER after granting consent in the browser..." -NoNewline
            $null = Read-Host
            
            # Run automatic validation check
            $valResult = Test-VulneriM365Onboarding -TenantId $activeTenantId -ClientId $app.AppId -Mode $Mode
            
            if ($valResult.validationStatus -eq "ready") {
                $validated = $true
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host "SUCCESS: Admin consent validated successfully!" -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host ""
                
                # Friendly summary
                Write-Host "== INSTALLATION SUMMARY ==" -ForegroundColor Cyan
                Write-Host "M365 Tenant ID: Customer's Microsoft 365 / Entra ID tenant."
                Write-Host "  -> $activeTenantId" -ForegroundColor Cyan
                Write-Host "M365 Client ID: App Registration created inside the customer's Microsoft 365 tenant."
                Write-Host "  -> $($app.AppId)" -ForegroundColor Cyan
                Write-Host "M365 Client Secret: Will be displayed only in the final JSON below."
                Write-Warn "Save this secret now. It will not be shown again."
                Write-Host ""
                Write-Info "This data will be registered in the Vulneri platform for the backend scanner to run."
                Write-Host ""
                
                $createdAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                $creationOutput = @{
                    provider             = "m365"
                    mode                 = $Mode.ToLower()
                    m365TenantId         = $activeTenantId
                    m365ClientId         = $app.AppId
                    m365ClientSecret     = $secretResult.SecretText
                    secretDisplayName   = $secretResult.DisplayName
                    secretExpiresAt     = $secretResult.ExpiresAt
                    createdAt            = $createdAt
                    permissionsRequested = $permissions
                    adminConsentUrl      = $consentUrl
                    onboardingStatus     = "ready"
                }
                
                Write-Host "============================================================" -ForegroundColor Cyan
                Write-Host "COPY AND PASTE THE JSON BELOW INTO THE VULNERI PLATFORM:" -ForegroundColor Cyan
                $json = ConvertTo-SafeJsonOutput -Payload $creationOutput
                Write-Host $json -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Cyan
                
                if ($WriteEnvFile) {
                    Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $app.AppId -ClientSecret $secretResult.SecretText -SecretExpiresAt $secretResult.ExpiresAt -Mode $Mode
                }
            } else {
                Write-Host ""
                Write-Err "Validation failed or is incomplete (Status: $($valResult.validationStatus))"
                if ($valResult.permissionsPendingConsent.Count -gt 0) {
                    Write-Err "Configured permissions pending administrator consent: $($valResult.permissionsPendingConsent -join ', ')"
                }
                if ($valResult.permissionsMissing.Count -gt 0) {
                    Write-Err "Missing permissions in the application configuration: $($valResult.permissionsMissing -join ', ')"
                }
                Write-Host ""
                
                Write-Host "Do you want to retry validation now? (Y/N): " -NoNewline
                $choice = ""
                if ([Environment]::UserInteractive) {
                    $choice = Read-Host
                } else {
                    Write-Warn "Non-interactive execution detected. Terminating validation loop."
                    $choice = "N"
                }
                
                if ($choice -notmatch "^[yYsS]") {
                    Write-Warn "Onboarding suspended. The App Registration was created, but credentials were not validated."
                    Write-Warn "To validate again later, run:"
                    Write-Warn "  ./m365_onboarding.ps1 -ValidateOnly -ClientId $($app.AppId) -TenantId $activeTenantId -Mode $Mode"
                    Write-Warn "If you closed this terminal and need to generate a new secret, run:"
                    Write-Warn "  ./m365_onboarding.ps1 -RenewSecret -ClientId $($app.AppId) -TenantId $activeTenantId"
                    break
                }
            }
        }
    }
}
catch {
    Write-Err "An unexpected error occurred during execution: $($_.Exception.Message)"
    exit 1
}<#
.SYNOPSIS
  Microsoft 365 Onboarding Script for Vulneri FinOps M365.
  
.DESCRIPTION
  This script automates the onboarding process of a Microsoft 365 tenant for Vulneri FinOps:
  - Creates or updates an Entra ID App Registration & Service Principal
  - Configures RequiredResourceAccess for either "Starter" or "Expert" permissions
  - Generates a client secret with custom expiration
  - Generates the Admin Consent URL
  - Performs validation checks on an existing client configuration
  - Renews client secrets

.EXAMPLE
  pwsh ./m365_onboarding.ps1 -Mode Starter
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "Vulneri FinOps M365",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Starter","Expert")]
    [string]$Mode = "Starter",

    [Parameter(Mandatory = $false)]
    [int]$SecretMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

    [Parameter(Mandatory = $false)]
    [switch]$RenewSecret,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [switch]$WriteEnvFile
)

# ==========================================
# 1. LOGGING FUNCTIONS (English Console Logs)
# ==========================================

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ==========================================
# 2. PARAMETER VALIDATION
# ==========================================

if ($ValidateOnly -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "The -ClientId parameter is required when -ValidateOnly is used."
    exit 1
}

if ($RenewSecret -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "The -ClientId parameter is required when -RenewSecret is used."
    exit 1
}

# ==========================================
# 3. MODULE AND CONNECTION FUNCTIONS
# ==========================================

function Ensure-GraphModule {
    Write-Info "Verifying PowerShell dependencies..."
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
    )

    foreach ($module in $requiredModules) {
        Write-Info "Checking $module..."
        $installed = Get-Module -ListAvailable -Name $module
        if (-not $installed) {
            Write-Info "Installing $module..."
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Info "$module installed successfully."
            }
            catch {
                Write-Err "Failed to install $module: $($_.Exception.Message)"
                Write-Err "Please run: Install-Module $module -Scope CurrentUser -Force -AllowClobber"
                exit 1
            }
        }

        Write-Info "Loading $module..."
        try {
            Import-Module $module -ErrorAction Stop
            Write-Info "$module loaded."
        }
        catch {
            Write-Err "Failed to load $module: $($_.Exception.Message)"
            exit 1
        }
    }

    # Validate required cmdlets
    $requiredCmdlets = @(
        "Connect-MgGraph",
        "Get-MgContext",
        "Get-MgApplication",
        "New-MgApplication",
        "Update-MgApplication",
        "Add-MgApplicationPassword",
        "Get-MgServicePrincipal",
        "New-MgServicePrincipal",
        "Get-MgServicePrincipalAppRoleAssignment"
    )

    Write-Info "Verifying required cmdlets..."
    $missingCmdlets = @()
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) {
            $missingCmdlets += $cmdlet
        }
    }

    if ($missingCmdlets.Count -gt 0) {
        Write-Err "The following required cmdlets are missing: $($missingCmdlets -join ', ')"
        Write-Err "Please reinstall the Graph modules by running the following commands:"
        Write-Err "  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber"
        Write-Err "  Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber"
        exit 1
    }
    Write-Info "All required cmdlets verified successfully."
}

function Connect-GraphForOnboarding {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    $scopes = @("Application.ReadWrite.All", "Directory.Read.All")
    Write-Info "Connecting to Microsoft Graph with required delegated scopes..."
    
    $connectParams = @{
        Scopes = $scopes
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrEmpty($TenantId)) {
        $connectParams["TenantId"] = $TenantId
    }
    
    Connect-MgGraph @connectParams | Out-Null
    
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Could not retrieve TenantId from the active Microsoft Graph context."
    }
    return $ctx.TenantId
}

# ==========================================
# 4. PERMISSIONS & ROLES RESOLUTION
# ==========================================

function Get-PermissionsForMode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    $starterPerms = @(
        "Directory.Read.All",
        "LicenseAssignment.Read.All",
        "Reports.Read.All",
        "MailboxSettings.Read",
        "ReportSettings.Read.All"
    )
    
    if ($Mode -eq "Expert") {
        $expertPerms = $starterPerms + @(
            "Policy.Read.All",
            "SecurityEvents.Read.All",
            "Application.Read.All",
            "AuditLog.Read.All",
            "RoleManagement.Read.Directory",
            "IdentityRiskyUser.Read.All"
        )
        return $expertPerms
    }
    
    return $starterPerms
}

function Get-GraphServicePrincipal {
    $graphAppId = "00000003-0000-0000-c000-000000000000"
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    if (-not $graphSp) {
        throw "Could not locate the Microsoft Graph Service Principal."
    }
    return $graphSp
}

function Resolve-GraphAppRoles {
    param(
        [Parameter(Mandatory = $true)]
        $GraphSp,
        [Parameter(Mandatory = $true)]
        [string[]]$Permissions
    )
    $appRoleMap = @{}
    foreach ($val in $Permissions) {
        $role = $GraphSp.AppRoles | Where-Object {
            $_.Value -eq $val -and $_.AllowedMemberTypes -contains "Application"
        }
        if (-not $role) {
            throw "The permission (AppRole) '$val' was not found in the Microsoft Graph Service Principal."
        }
        $appRoleMap[$val] = $role.Id
    }
    return $appRoleMap
}

# ==========================================
# 5. APP REGISTRATION MANAGEMENT
# ==========================================

function New-VulneriM365Application {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,
        [Parameter(Mandatory = $true)]
        [hashtable]$AppRoleMap,
        [Parameter(Mandatory = $true)]
        [string[]]$Permissions
    )
    $graphAppId = "00000003-0000-0000-c000-000000000000"
    
    Write-Info "Checking if an App Registration named '$DisplayName' already exists..."
    $existingApps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    $app = $null
    if ($existingApps) {
        Write-Warn "An App Registration with the name '$DisplayName' already exists in your tenant."
        
        $choice = ""
        if ([Environment]::UserInteractive) {
            Write-Host "Do you want to reuse the existing App Registration? (Y/N): " -NoNewline
            $choice = Read-Host
        } else {
            Write-Warn "Non-interactive execution detected. Reusing the existing App Registration by default."
            $choice = "Y"
        }
        
        if ($choice -match "^[yYsS]") {
            $app = $existingApps[0]
            Write-Info "Reusing existing App Registration. Application ID (ClientId): $($app.AppId)"
        } else {
            Write-Info "Creating a new App Registration with the same name..."
        }
    }
    
    $resourceAccess = @()
    foreach ($val in $Permissions) {
        $resourceAccess += @{
            Id   = $AppRoleMap[$val]
            Type = "Role"
        }
    }
    
    $requiredResourceAccess = @(
        @{
            ResourceAppId  = $graphAppId
            ResourceAccess = $resourceAccess
        }
    )
    
    if ($app) {
        Write-Info "Updating configured permissions on the App Registration..."
        $updateParams = @{
            RequiredResourceAccess = $requiredResourceAccess
        }
        Update-MgApplication -ApplicationId $app.Id @updateParams -ErrorAction Stop
        # Fetch the updated app object to return
        $app = Get-MgApplication -ApplicationId $app.Id -ErrorAction Stop
    } else {
        Write-Info "Creating a new App Registration..."
        $appParams = @{
            DisplayName            = $DisplayName
            SignInAudience         = "AzureADMyOrg"
            RequiredResourceAccess = $requiredResourceAccess
            Web                    = @{
                RedirectUris = @("https://localhost")
            }
        }
        $app = New-MgApplication @appParams -ErrorAction Stop
        Write-Info "App Registration created successfully."
    }
    
    Write-Info "Ensuring corresponding Service Principal exists..."
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Info "Creating Service Principal..."
        $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        Write-Info "Service Principal created successfully."
    } else {
        Write-Info "Service Principal already exists."
    }
    
    return [pscustomobject]@{
        Application      = $app
        ServicePrincipal = $sp
    }
}

function New-VulneriM365Secret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)]
        [int]$SecretMonths
    )
    Write-Info "Adding a new client secret..."
    $secretDisplayName = "vulneri-finops-secret"
    $endDate = (Get-Date).AddMonths($SecretMonths)
    
    $passwordCred = @{
        displayName  = $secretDisplayName
        endDateTime  = $endDate.ToUniversalTime()
    }
    
    $secretObj = Add-MgApplicationPassword -ApplicationId $ApplicationObjectId -PasswordCredential $passwordCred -ErrorAction Stop
    $clientSecret = $secretObj.SecretText
    
    if (-not $clientSecret) {
        throw "Failed to generate Client Secret (empty return value)."
    }
    
    return [pscustomobject]@{
        SecretText  = $clientSecret
        DisplayName = $secretDisplayName
        ExpiresAt   = $endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

function Get-AdminConsentUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId
    )
    $redirectUri = [System.Net.WebUtility]::UrlEncode("https://localhost")
    $scope = [System.Net.WebUtility]::UrlEncode("https://graph.microsoft.com/.default")
    $adminConsentUrl = "https://login.microsoftonline.com/$TenantId/v2.0/adminconsent?client_id=$ClientId&scope=$scope&redirect_uri=$redirectUri"
    return $adminConsentUrl
}

# ==========================================
# 6. VALIDATION AND RENEWAL
# ==========================================

function Test-VulneriM365Onboarding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    Write-Info "Starting App Registration validation for ClientId: $ClientId..."
    
    $permissionsExpected = Get-PermissionsForMode -Mode $Mode
    $checkedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    try {
        # Find application
        Write-Info "Locating App Registration..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration with ClientId '$ClientId' was not found."
        }
        
        # Find Service Principal
        Write-Info "Locating Service Principal..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $sp) {
            throw "Corresponding Service Principal for ClientId '$ClientId' was not found."
        }
        
        # Get Graph SP
        $graphSp = Get-GraphServicePrincipal
        $graphAppId = "00000003-0000-0000-c000-000000000000"
        
        # Build maps
        $idToNameMap = @{}
        foreach ($role in $graphSp.AppRoles) {
            $idToNameMap[$role.Id.ToString()] = $role.Value
        }
        
        # Get configured permissions
        $permissionsConfigured = @()
        if ($app.RequiredResourceAccess) {
            $graphAccess = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $graphAppId }
            if ($graphAccess -and $graphAccess.ResourceAccess) {
                foreach ($acc in $graphAccess.ResourceAccess) {
                    $roleId = $acc.Id.ToString()
                    if ($idToNameMap.ContainsKey($roleId)) {
                        $permissionsConfigured += $idToNameMap[$roleId]
                    } else {
                        $permissionsConfigured += $roleId
                    }
                }
            }
        }
        
        # Get granted permissions
        $permissionsGranted = @()
        Write-Info "Fetching permissions with admin consent..."
        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
        if ($assignments) {
            $graphAssignments = $assignments | Where-Object { $_.ResourceId -eq $graphSp.Id }
            foreach ($asg in $graphAssignments) {
                $roleId = $asg.AppRoleId.ToString()
                if ($idToNameMap.ContainsKey($roleId)) {
                    $permissionsGranted += $idToNameMap[$roleId]
                } else {
                    $permissionsGranted += $roleId
                }
            }
        }
        
        # Calculate missing and pending
        $permissionsMissing = @()
        foreach ($expected in $permissionsExpected) {
            if ($expected -notin $permissionsConfigured) {
                $permissionsMissing += $expected
            }
        }
        
        $permissionsPendingConsent = @()
        foreach ($expected in $permissionsExpected) {
            if ($expected -in $permissionsConfigured -and $expected -notin $permissionsGranted) {
                $permissionsPendingConsent += $expected
            }
        }
        
        # Validation status
        $validationStatus = "ready"
        if ($permissionsMissing.Count -gt 0) {
            $validationStatus = "missing_permissions"
            Write-Warn "Validation: Some expected permissions are not configured in RequiredResourceAccess."
        }
        elseif ($permissionsPendingConsent.Count -gt 0) {
            $validationStatus = "pending_admin_consent"
            Write-Warn "Validation: Configured permissions are pending administrator consent."
        }
        else {
            Write-Info "Validation: All set! All required permissions have been configured and consented."
        }
        
        $output = @{
            provider                   = "m365"
            mode                       = $Mode.ToLower()
            m365TenantId               = $TenantId
            m365ClientId               = $ClientId
            validationStatus           = $validationStatus
            permissionsExpected        = $permissionsExpected
            permissionsConfigured      = $permissionsConfigured
            permissionsMissing         = $permissionsMissing
            permissionsGranted         = $permissionsGranted
            permissionsPendingConsent  = $permissionsPendingConsent
            checkedAt                  = $checkedAt
        }
        
        return $output
    }
    catch {
        Write-Err "Error during validation: $($_.Exception.Message)"
        return @{
            provider                   = "m365"
            mode                       = $Mode.ToLower()
            m365TenantId               = $TenantId
            m365ClientId               = $ClientId
            validationStatus           = "error"
            errorMessage               = $_.Exception.Message
            permissionsExpected        = $permissionsExpected
            permissionsConfigured      = @()
            permissionsMissing         = $permissionsExpected
            permissionsGranted         = @()
            permissionsPendingConsent  = @()
            checkedAt                  = $checkedAt
        }
    }
}

function Renew-VulneriM365Secret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [int]$SecretMonths
    )
    Write-Info "Starting Client Secret renewal for ClientId: $ClientId..."
    
    try {
        Write-Info "Locating the App Registration in the tenant..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration with ClientId '$ClientId' was not found."
        }
        
        $secret = New-VulneriM365Secret -ApplicationObjectId $app.Id -SecretMonths $SecretMonths
        $renewedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $output = @{
            provider            = "m365"
            m365TenantId        = $TenantId
            m365ClientId        = $ClientId
            m365ClientSecret    = $secret.SecretText
            secretDisplayName   = $secret.DisplayName
            secretExpiresAt     = $secret.ExpiresAt
            renewedAt           = $renewedAt
            onboardingStatus    = "secret_renewed"
        }
        
        return $output
    }
    catch {
        Write-Err "Error renewing secret: $($_.Exception.Message)"
        exit 1
    }
}

# ==========================================
# 7. OUTPUT MANAGEMENT
# ==========================================

function ConvertTo-SafeJsonOutput {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Payload
    )
    return $Payload | ConvertTo-Json -Depth 5 -Compress
}

function Write-OptionalEnvFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $false)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $false)]
        [string]$SecretExpiresAt,
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    $envPath = Join-Path -Path (Get-Location) -ChildPath ".env"
    
    if (Test-Path $envPath) {
        Write-Warn "The '.env' file already exists in the current directory and will be overwritten."
    }
    
    $lines = @(
        "M365_TENANT_ID=$TenantId",
        "M365_CLIENT_ID=$ClientId"
    )
    if (-not [string]::IsNullOrEmpty($ClientSecret)) {
        $lines += "M365_CLIENT_SECRET=$ClientSecret"
    }
    if (-not [string]::IsNullOrEmpty($SecretExpiresAt)) {
        $lines += "M365_SECRET_EXPIRES_AT=$SecretExpiresAt"
    }
    $lines += "M365_ONBOARDING_MODE=$($Mode.ToLower())"
    
    $lines | Out-File -FilePath $envPath -Encoding ascii -Force
    
    Write-Warn "============================================================"
    Write-Warn "SECURITY WARNING: .env file generated at: $envPath"
    Write-Warn "Use -WriteEnvFile for testing or controlled environments only."
    Write-Warn "This file contains highly sensitive credentials."
    Write-Warn "Never commit this file to Git repositories or share it."
    Write-Warn "============================================================"
}

# ==========================================
# 8. CORE EXECUTION LOGIC
# ==========================================

try {
    Write-Host "== Vulneri Microsoft 365 Onboarding ==" -ForegroundColor Cyan
    Write-Info "This script only configures Microsoft 365 access. The scanner will run on the Vulneri backend."
    Write-Info "Local machine administrator privileges are not required; tenant administrator privileges may be needed."
    
    if ($ValidateOnly) {
        Write-Info "Selected mode: Permission Validation (-ValidateOnly)"
    } elseif ($RenewSecret) {
        Write-Info "Selected mode: Credential Renewal (-RenewSecret)"
    } else {
        Write-Info "Selected mode: $Mode"
        if ($Mode -eq "Starter") {
            Write-Info "This mode requests only read-only permissions for license inventory and usage."
        } else {
            Write-Info "This mode requests additional permissions for security, governance, identity, and applications."
        }
    }
    Write-Host ""
    
    # Check dependencies and module
    Ensure-GraphModule
    
    # Establish connection and infer or validate TenantId
    $activeTenantId = Connect-GraphForOnboarding -TenantId $TenantId
    
    if ($ValidateOnly) {
        # Perform validation
        $valOutput = Test-VulneriM365Onboarding -TenantId $activeTenantId -ClientId $ClientId -Mode $Mode
        
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "VALIDATION RESULT (JSON):" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $valOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $ClientId -Mode $Mode
        }
    }
    elseif ($RenewSecret) {
        # Perform secret renewal
        $renewOutput = Renew-VulneriM365Secret -TenantId $activeTenantId -ClientId $ClientId -SecretMonths $SecretMonths
        
        Write-Host ""
        Write-Warn "Recommendation: Remove old secrets in the Azure/Entra console only after validating the new credential on the Vulneri platform."
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "COPY AND PASTE THE JSON BELOW INTO THE VULNERI PLATFORM:" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $renewOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $ClientId -ClientSecret $renewOutput.m365ClientSecret -SecretExpiresAt $renewOutput.secretExpiresAt -Mode $Mode
        }
    }
    else {
        # Creation flow
        $permissions = Get-PermissionsForMode -Mode $Mode
        
        Write-Info "Locating Service Principal do Microsoft Graph..."
        $graphSp = Get-GraphServicePrincipal
        $appRoleMap = Resolve-GraphAppRoles -GraphSp $graphSp -Permissions $permissions
        
        $appResult = New-VulneriM365Application -DisplayName $DisplayName -AppRoleMap $appRoleMap -Permissions $permissions
        $app = $appResult.Application
        
        # Create client secret, but DO NOT print it yet!
        $secretResult = New-VulneriM365Secret -ApplicationObjectId $app.Id -SecretMonths $SecretMonths
        $consentUrl = Get-AdminConsentUrl -TenantId $activeTenantId -ClientId $app.AppId
        
        # Interactive Admin Consent validation loop
        $validated = $false
        while (-not $validated) {
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host "ACTION REQUIRED: GRANT ADMINISTRATOR CONSENT" -ForegroundColor Yellow
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host "The App Registration has been created in the customer's Microsoft 365 tenant,"
            Write-Host "but is NOT yet authorized to read the data."
            Write-Host ""
            Write-Host "Before registering credentials on the Vulneri platform, a tenant administrator"
            Write-Host "needs to grant consent for the requested permissions."
            Write-Host ""
            Write-Host "Who can do this:"
            Write-Host "- Global Administrator"
            Write-Host "- Privileged Role Administrator"
            Write-Host "- or equivalent role with permissions to grant admin consent"
            Write-Host ""
            Write-Host "The Vulneri scanner will NOT be able to run until this consent"
            Write-Host "is granted."
            Write-Host ""
            Write-Host "Open the URL below in your browser, review the permissions, and click Accept."
            Write-Host "Then return to this terminal and press ENTER to validate."
            Write-Host ""
            Write-Host "Important:"
            Write-Host "The secret was created, but will only be displayed after consent"
            Write-Host "is successfully validated. If this terminal is closed before then,"
            Write-Host "you will need to generate a new secret using -RenewSecret."
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Admin Consent URL:" -ForegroundColor Yellow
            Write-Host "  $consentUrl" -ForegroundColor Cyan
            Write-Host ""
            
            # Browser auto-opening logic (if local and safe)
            $isCloudShell = $env:AZURE_HTTP_USER_AGENT -like "*cloud-shell*" -or $env:ACC_TERM_ID
            if (-not $isCloudShell) {
                try {
                    Write-Info "Attempting to open the URL in your browser automatically..."
                    if ($IsWindows) {
                        Start-Process $consentUrl
                    } elseif ($IsMacOS) {
                        Start-Process "open" $consentUrl
                    } elseif ($IsLinux) {
                        Start-Process "xdg-open" $consentUrl
                    } else {
                        # Fallback for compatibility with older PowerShell hosts
                        Start-Process $consentUrl
                    }
                }
                catch {
                    Write-Warn "Could not open the browser automatically: $($_.Exception.Message)"
                    Write-Warn "Please copy and paste the URL above manually into your browser."
                }
            } else {
                Write-Info "Running in Azure Cloud Shell. Please copy and paste the URL above manually into your browser."
            }
            
            Write-Host ""
            Write-Host "Press ENTER after granting consent in the browser..." -NoNewline
            $null = Read-Host
            
            # Run automatic validation check
            $valResult = Test-VulneriM365Onboarding -TenantId $activeTenantId -ClientId $app.AppId -Mode $Mode
            
            if ($valResult.validationStatus -eq "ready") {
                $validated = $true
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host "SUCCESS: Admin consent validated successfully!" -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host ""
                
                # Friendly summary
                Write-Host "== INSTALLATION SUMMARY ==" -ForegroundColor Cyan
                Write-Host "M365 Tenant ID: Customer's Microsoft 365 / Entra ID tenant."
                Write-Host "  -> $activeTenantId" -ForegroundColor Cyan
                Write-Host "M365 Client ID: App Registration created inside the customer's Microsoft 365 tenant."
                Write-Host "  -> $($app.AppId)" -ForegroundColor Cyan
                Write-Host "M365 Client Secret: Will be displayed only in the final JSON below."
                Write-Warn "Save this secret now. It will not be shown again."
                Write-Host ""
                Write-Info "This data will be registered in the Vulneri platform for the backend scanner to run."
                Write-Host ""
                
                $createdAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                $creationOutput = @{
                    provider             = "m365"
                    mode                 = $Mode.ToLower()
                    m365TenantId         = $activeTenantId
                    m365ClientId         = $app.AppId
                    m365ClientSecret     = $secretResult.SecretText
                    secretDisplayName   = $secretResult.DisplayName
                    secretExpiresAt     = $secretResult.ExpiresAt
                    createdAt            = $createdAt
                    permissionsRequested = $permissions
                    adminConsentUrl      = $consentUrl
                    onboardingStatus     = "ready"
                }
                
                Write-Host "============================================================" -ForegroundColor Cyan
                Write-Host "COPY AND PASTE THE JSON BELOW INTO THE VULNERI PLATFORM:" -ForegroundColor Cyan
                $json = ConvertTo-SafeJsonOutput -Payload $creationOutput
                Write-Host $json -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Cyan
                
                if ($WriteEnvFile) {
                    Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $app.AppId -ClientSecret $secretResult.SecretText -SecretExpiresAt $secretResult.ExpiresAt -Mode $Mode
                }
            } else {
                Write-Host ""
                Write-Err "Validation failed or is incomplete (Status: $($valResult.validationStatus))"
                if ($valResult.permissionsPendingConsent.Count -gt 0) {
                    Write-Err "Configured permissions pending administrator consent: $($valResult.permissionsPendingConsent -join ', ')"
                }
                if ($valResult.permissionsMissing.Count -gt 0) {
                    Write-Err "Missing permissions in the application configuration: $($valResult.permissionsMissing -join ', ')"
                }
                Write-Host ""
                
                Write-Host "Do you want to retry validation now? (Y/N): " -NoNewline
                $choice = ""
                if ([Environment]::UserInteractive) {
                    $choice = Read-Host
                } else {
                    Write-Warn "Non-interactive execution detected. Terminating validation loop."
                    $choice = "N"
                }
                
                if ($choice -notmatch "^[yYsS]") {
                    Write-Warn "Onboarding suspended. The App Registration was created, but credentials were not validated."
                    Write-Warn "To validate again later, run:"
                    Write-Warn "  ./m365_onboarding.ps1 -ValidateOnly -ClientId $($app.AppId) -TenantId $activeTenantId -Mode $Mode"
                    Write-Warn "If you closed this terminal and need to generate a new secret, run:"
                    Write-Warn "  ./m365_onboarding.ps1 -RenewSecret -ClientId $($app.AppId) -TenantId $activeTenantId"
                    break
                }
            }
        }
    }
}
catch {
    Write-Err "An unexpected error occurred during execution: $($_.Exception.Message)"
    exit 1
}
