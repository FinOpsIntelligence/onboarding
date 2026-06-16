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
# 1. LOGGING FUNCTIONS (Portuguese Console Logs)
# ==========================================

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[AVISO] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERRO] $Message" -ForegroundColor Red
}

# ==========================================
# 2. PARAMETER VALIDATION
# ==========================================

if ($ValidateOnly -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "O parâmetro -ClientId é obrigatório quando -ValidateOnly for utilizado."
    exit 1
}

if ($RenewSecret -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "O parâmetro -ClientId é obrigatório quando -RenewSecret for utilizado."
    exit 1
}

# ==========================================
# 3. MODULE AND CONNECTION FUNCTIONS
# ==========================================

function Ensure-GraphModule {
    Write-Info "Verificando dependências do PowerShell..."
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Warn "Módulo 'Microsoft.Graph' não encontrado. Instalando..."
        try {
            # Install in CurrentUser scope to avoid administrative prompt requirement
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Info "Módulo Microsoft.Graph instalado com sucesso."
        }
        catch {
            Write-Err "Falha ao instalar o módulo Microsoft.Graph: $($_.Exception.Message)"
            Write-Err "Instale manualmente com (por exemplo):"
            Write-Err "  Install-Module Microsoft.Graph -Scope CurrentUser -Force"
            exit 1
        }
    }

    try {
        Import-Module Microsoft.Graph -ErrorAction Stop
    }
    catch {
        Write-Err "Falha ao importar o módulo Microsoft.Graph: $($_.Exception.Message)"
        exit 1
    }
}

function Connect-GraphForOnboarding {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    $scopes = @("Application.ReadWrite.All", "Directory.Read.All")
    Write-Info "Conectando ao Microsoft Graph com os escopos delegados necessários..."
    
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
        throw "Não foi possível obter o TenantId a partir do contexto ativo do Microsoft Graph."
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
        throw "Não foi possível localizar o Service Principal do Microsoft Graph."
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
            throw "A permissão (AppRole) '$val' não foi encontrada no Service Principal do Microsoft Graph."
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
    
    Write-Info "Verificando se já existe um App Registration com o nome '$DisplayName'..."
    $existingApps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    $app = $null
    if ($existingApps) {
        Write-Warn "Já existe um App Registration com o nome '$DisplayName' no seu tenant."
        
        $choice = ""
        if ([Environment]::UserInteractive) {
            Write-Host "Deseja reutilizar o App Registration existente? (S/N): " -NoNewline
            $choice = Read-Host
        } else {
            Write-Warn "Execução não interativa detectada. Reutilizando o App Registration existente por padrão."
            $choice = "S"
        }
        
        if ($choice -match "^[sSyY]") {
            $app = $existingApps[0]
            Write-Info "Reutilizando App Registration existente. ID do Aplicativo (ClientId): $($app.AppId)"
        } else {
            Write-Info "Criando um novo App Registration com o mesmo nome..."
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
        Write-Info "Atualizando as permissões configuradas no App Registration..."
        $updateParams = @{
            RequiredResourceAccess = $requiredResourceAccess
        }
        Update-MgApplication -ApplicationId $app.Id @updateParams -ErrorAction Stop
        # Fetch the updated app object to return
        $app = Get-MgApplication -ApplicationId $app.Id -ErrorAction Stop
    } else {
        Write-Info "Criando novo App Registration..."
        $appParams = @{
            DisplayName            = $DisplayName
            SignInAudience         = "AzureADMyOrg"
            RequiredResourceAccess = $requiredResourceAccess
            Web                    = @{
                RedirectUris = @("https://localhost")
            }
        }
        $app = New-MgApplication @appParams -ErrorAction Stop
        Write-Info "App Registration criado com sucesso."
    }
    
    Write-Info "Garantindo a existência do Service Principal correspondente..."
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Info "Criando Service Principal..."
        $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        Write-Info "Service Principal criado com sucesso."
    } else {
        Write-Info "Service Principal já existe."
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
    Write-Info "Adicionando uma nova client secret..."
    $secretDisplayName = "vulneri-finops-secret"
    $endDate = (Get-Date).AddMonths($SecretMonths)
    
    $passwordCred = @{
        displayName  = $secretDisplayName
        endDateTime  = $endDate.ToUniversalTime()
    }
    
    $secretObj = Add-MgApplicationPassword -ApplicationId $ApplicationObjectId -PasswordCredential $passwordCred -ErrorAction Stop
    $clientSecret = $secretObj.SecretText
    
    if (-not $clientSecret) {
        throw "Falha ao gerar o Client Secret (retorno vazio)."
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
    Write-Info "Iniciando validação do App Registration para o ClientId: $ClientId..."
    
    $permissionsExpected = Get-PermissionsForMode -Mode $Mode
    $checkedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    try {
        # Find application
        Write-Info "Localizando App Registration..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration com ClientId '$ClientId' não foi encontrado."
        }
        
        # Find Service Principal
        Write-Info "Localizando Service Principal..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $sp) {
            throw "Service Principal correspondente ao ClientId '$ClientId' não foi encontrado."
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
        Write-Info "Buscando permissões com consentimento administrativo..."
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
            Write-Warn "Validação: Algumas permissões esperadas não estão configuradas no RequiredResourceAccess."
        }
        elseif ($permissionsPendingConsent.Count -gt 0) {
            $validationStatus = "pending_admin_consent"
            Write-Warn "Validação: Há permissões configuradas aguardando consentimento do administrador."
        }
        else {
            Write-Info "Validação: Tudo pronto! Todas as permissões necessárias foram configuradas e consentidas."
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
        Write-Err "Erro durante a validação: $($_.Exception.Message)"
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
    Write-Info "Iniciando a renovação do Client Secret para o ClientId: $ClientId..."
    
    try {
        Write-Info "Localizando o App Registration no tenant..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration com ClientId '$ClientId' não foi encontrado."
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
        Write-Err "Erro ao renovar a secret: $($_.Exception.Message)"
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
        Write-Warn "O arquivo '.env' já existe no diretório atual e será sobrescrito."
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
    Write-Warn "AVISO DE SEGURANÇA: Arquivo .env gerado em: $envPath"
    Write-Warn "Use -WriteEnvFile apenas para testes ou ambientes controlados."
    Write-Warn "Este arquivo contém credenciais altamente confidenciais."
    Write-Warn "Nunca comite este arquivo em repositórios Git ou compartilhe-o."
    Write-Warn "============================================================"
}

# ==========================================
# 8. CORE EXECUTION LOGIC
# ==========================================

try {
    Write-Host "== Vulneri Microsoft 365 Onboarding ==" -ForegroundColor Cyan
    Write-Info "Este script apenas configura o acesso Microsoft 365. O scanner será executado no backend da Vulneri."
    Write-Info "Não é necessário administrador local da máquina; pode ser necessário administrador do tenant Microsoft."
    
    if ($ValidateOnly) {
        Write-Info "Modo selecionado: Validação de Permissões (-ValidateOnly)"
    } elseif ($RenewSecret) {
        Write-Info "Modo selecionado: Renovação de Credenciais (-RenewSecret)"
    } else {
        Write-Info "Modo selecionado: $Mode"
        if ($Mode -eq "Starter") {
            Write-Info "Este modo solicita apenas permissões de leitura para inventário de licenças e uso."
        } else {
            Write-Info "Este modo solicita permissões adicionais para segurança, governança, identidade e aplicações."
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
        Write-Host "RESULTADO DA VALIDAÇÃO (JSON):" -ForegroundColor Cyan
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
        Write-Warn "Recomendação: Remova as secrets antigas na console do Azure/Entra somente depois de validar a nova credencial na plataforma Vulneri."
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "COPIE E COLE O JSON ABAIXO NA PLATAFORMA VULNERI:" -ForegroundColor Cyan
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
        
        Write-Info "Localizando Service Principal do Microsoft Graph..."
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
            Write-Host "AÇÃO NECESSÁRIA: CONCEDER CONSENTIMENTO ADMINISTRATIVO" -ForegroundColor Yellow
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host "O App Registration foi criado no tenant Microsoft 365 do cliente,"
            Write-Host "mas ainda NÃO está autorizado para leitura dos dados."
            Write-Host ""
            Write-Host "Antes de cadastrar as credenciais na plataforma Vulneri, um administrador"
            Write-Host "do tenant precisa conceder consentimento para as permissões solicitadas."
            Write-Host ""
            Write-Host "Quem pode fazer isso:"
            Write-Host "- Global Administrator"
            Write-Host "- Privileged Role Administrator"
            Write-Host "- ou papel equivalente com permissão para conceder admin consent"
            Write-Host ""
            Write-Host "O scanner da Vulneri NÃO conseguirá executar até que este consentimento"
            Write-Host "seja concedido."
            Write-Host ""
            Write-Host "Abra a URL abaixo no navegador, revise as permissões e clique em Aceitar."
            Write-Host "Depois volte para este terminal e pressione ENTER para validar."
            Write-Host ""
            Write-Host "Importante:"
            Write-Host "A secret foi criada, mas só será exibida depois que o consentimento"
            Write-Host "for validado com sucesso. Se este terminal for fechado antes disso,"
            Write-Host "será necessário gerar uma nova secret com -RenewSecret."
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Admin Consent URL:" -ForegroundColor Yellow
            Write-Host "  $consentUrl" -ForegroundColor Cyan
            Write-Host ""
            
            # Browser auto-opening logic (if local and safe)
            $isCloudShell = $env:AZURE_HTTP_USER_AGENT -like "*cloud-shell*" -or $env:ACC_TERM_ID
            if (-not $isCloudShell) {
                try {
                    Write-Info "Tentando abrir a URL no seu navegador automaticamente..."
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
                    Write-Warn "Não foi possível abrir o navegador automaticamente: $($_.Exception.Message)"
                    Write-Warn "Por favor, copie e cole a URL acima manualmente no seu navegador."
                }
            } else {
                Write-Info "Executando no Azure Cloud Shell. Copie e cole a URL acima manualmente no seu navegador."
            }
            
            Write-Host ""
            Write-Host "Pressione ENTER após conceder o consentimento no navegador..." -NoNewline
            $null = Read-Host
            
            # Run automatic validation check
            $valResult = Test-VulneriM365Onboarding -TenantId $activeTenantId -ClientId $app.AppId -Mode $Mode
            
            if ($valResult.validationStatus -eq "ready") {
                $validated = $true
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host "SUCESSO: Consentimento administrativo validado com sucesso!" -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host ""
                
                # Friendly summary
                Write-Host "== RESUMO DE INSTALAÇÃO ==" -ForegroundColor Cyan
                Write-Host "M365 Tenant ID: tenant Microsoft 365 / Entra ID do cliente."
                Write-Host "  -> $activeTenantId" -ForegroundColor Cyan
                Write-Host "M365 Client ID: App Registration criado dentro do tenant Microsoft 365 do cliente."
                Write-Host "  -> $($app.AppId)" -ForegroundColor Cyan
                Write-Host "M365 Client Secret: será exibido somente no JSON final abaixo."
                Write-Warn "Guarde este segredo agora. Ele não será exibido novamente."
                Write-Host ""
                Write-Info "Esses dados serão cadastrados na plataforma Vulneri para que o scanner rode no backend."
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
                Write-Host "COPIE E COLE O JSON ABAIXO NA PLATAFORMA VULNERI:" -ForegroundColor Cyan
                $json = ConvertTo-SafeJsonOutput -Payload $creationOutput
                Write-Host $json -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Cyan
                
                if ($WriteEnvFile) {
                    Write-OptionalEnvFile -TenantId $activeTenantId -ClientId $app.AppId -ClientSecret $secretResult.SecretText -SecretExpiresAt $secretResult.ExpiresAt -Mode $Mode
                }
            } else {
                Write-Host ""
                Write-Err "A validação falhou ou está incompleta (Status: $($valResult.validationStatus))"
                if ($valResult.permissionsPendingConsent.Count -gt 0) {
                    Write-Err "Permissões configuradas aguardando consentimento do administrador: $($valResult.permissionsPendingConsent -join ', ')"
                }
                if ($valResult.permissionsMissing.Count -gt 0) {
                    Write-Err "Permissões ausentes na configuração do aplicativo: $($valResult.permissionsMissing -join ', ')"
                }
                Write-Host ""
                
                Write-Host "Deseja tentar a validação novamente agora? (S/N): " -NoNewline
                $choice = ""
                if ([Environment]::UserInteractive) {
                    $choice = Read-Host
                } else {
                    Write-Warn "Execução não interativa detectada. Encerrando loop de validação."
                    $choice = "N"
                }
                
                if ($choice -notmatch "^[sSyY]") {
                    Write-Warn "Onboarding suspenso. O App Registration foi criado, mas as credenciais não foram validadas."
                    Write-Warn "Para validar novamente mais tarde, execute:"
                    Write-Warn "  ./m365_onboarding.ps1 -ValidateOnly -ClientId $($app.AppId) -TenantId $activeTenantId -Mode $Mode"
                    Write-Warn "Caso tenha fechado este terminal e precise gerar uma nova secret, execute:"
                    Write-Warn "  ./m365_onboarding.ps1 -RenewSecret -ClientId $($app.AppId) -TenantId $activeTenantId"
                    break
                }
            }
        }
    }
}
catch {
    Write-Err "Ocorreu um erro inesperado durante a execução: $($_.Exception.Message)"
    exit 1
}
