<#
.SYNOPSIS
  Script de Onboarding do Microsoft 365 para Vulneri FinOps M365.
  
.DESCRIPTION
  Este script automatiza o processo de onboarding de um tenant do Microsoft 365 para a Vulneri FinOps:
  - Cria ou atualiza um App Registration & Service Principal no Entra ID
  - Configura RequiredResourceAccess para permissoes de modo "Starter" ou "Expert"
  - Tenta conceder o consentimento de administrador de forma automatica
  - Gera uma chave secreta (client secret) com expiracao customizada
  - Gera a URL de consentimento caso falhe a concessao automatica
  - Executa testes de validacao na configuracao final das permissoes
  - Renova segredos de aplicativos existentes
  - Valida permissoes de registros existentes

.EXAMPLE
  pwsh ./m365_onboarding.ps1 -Mode Starter
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Starter","Expert")]
    [string]$Mode = "Starter",

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "Vulneri FinOps M365",

    [Parameter(Mandatory = $false)]
    [int]$SecretMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

    [Parameter(Mandatory = $false)]
    [switch]$RenewSecret,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [switch]$WriteEnvFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Auto","Browser","DeviceCode")]
    [string]$LoginMode = "Auto"
)

# ==========================================
# 1. FUNCOES DE LOGGING (Portugues)
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
# 2. VALIDACAO DE PARAMETROS INICIAIS
# ==========================================

if ($ValidateOnly -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "O parametro -ClientId e obrigatorio quando -ValidateOnly e utilizado."
    exit 1
}

if ($RenewSecret -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "O parametro -ClientId e obrigatorio quando -RenewSecret e utilizado."
    exit 1
}

# ==========================================
# 3. VERIFICACAO DE DEPENDENCIAS DO GRAPH
# ==========================================

function Ensure-GraphModules {
    Write-Info "Verificando dependencias do PowerShell..."
    
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        try {
            Write-Info "Garantindo NuGet package provider..."
            Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch {
            Write-Err "Falha ao instalar o NuGet Package Provider - $($_.Exception.Message)"
            Write-Err "Por favor, execute o script em uma versao do PowerShell 7+ ou certifique-se de executar como um usuario com privilegios para instalar modulos em CurrentUser."
        }
    }

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
    )

    foreach ($module in $requiredModules) {
        Write-Info "Verificando modulo $module..."
        $installed = Get-Module -ListAvailable -Name $module
        if (-not $installed) {
            Write-Info "Instalando modulo $module..."
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Info "Modulo $module instalado com sucesso."
            }
            catch {
                Write-Err "Falha ao instalar o modulo $module - $($_.Exception.Message)"
                Write-Err "Por favor, execute manualmente: Install-Module $module -Scope CurrentUser -Force -AllowClobber"
                exit 1
            }
        }

        Write-Info "Carregando modulo $module..."
        try {
            Import-Module $module -ErrorAction Stop
            Write-Info "Modulo $module carregado com sucesso."
        }
        catch {
            Write-Err "Falha ao carregar o modulo $module - $($_.Exception.Message)"
            exit 1
        }
    }

    # Validar cmdlets obrigatorios
    $requiredCmdlets = @(
        "Connect-MgGraph",
        "Get-MgContext",
        "Get-MgApplication",
        "New-MgApplication",
        "Update-MgApplication",
        "Add-MgApplicationPassword",
        "Get-MgServicePrincipal",
        "New-MgServicePrincipal",
        "Get-MgServicePrincipalAppRoleAssignment",
        "New-MgServicePrincipalAppRoleAssignment",
        "Invoke-MgGraphRequest"
    )

    Write-Info "Validando cmdlets obrigatorios..."
    $missingCmdlets = @()
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) {
            $missingCmdlets += $cmdlet
        }
    }

    if ($missingCmdlets.Count -gt 0) {
        Write-Err "Os seguintes cmdlets obrigatorios estao ausentes: $($missingCmdlets -join ', ')"
        Write-Err "Por favor, reinstale os modulos executando:"
        Write-Err "  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber"
        Write-Err "  Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber"
        exit 1
    }
    Write-Info "Todos os cmdlets obrigatorios foram validados com sucesso."
}

# ==========================================
# 4. AUTENTICACAO E METADADOS DO TENANT
# ==========================================

function Connect-M365Tenant {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        [Parameter(Mandatory = $false)]
        [string]$LoginMode = "Auto"
    )
    $scopes = @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.Read.All")
    Write-Info "Conectando ao Microsoft Graph com escopos delegados necessarios..."
    
    Write-Host ""
    Write-Host "************************************************************" -ForegroundColor Yellow
    Write-Host "                    LOGIN MICROSOFT 365                     " -ForegroundColor White -BackgroundColor Red
    Write-Host "************************************************************" -ForegroundColor Yellow
    Write-Host "O script vai abrir uma janela do navegador para voce fazer login" -ForegroundColor Cyan
    Write-Host "com uma conta administrativa do Microsoft 365." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Se o navegador nao abrir automaticamente, o script usara o modo" -ForegroundColor Cyan
    Write-Host "codigo de dispositivo como alternativa." -ForegroundColor Cyan
    Write-Host "************************************************************" -ForegroundColor Yellow
    Write-Host ""
    
    $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    $connectParams = @{
        Scopes       = $scopes
        ContextScope = "Process"
        ErrorAction  = "Stop"
    }

    if (-not [string]::IsNullOrEmpty($TenantId)) {
        $connectParams["TenantId"] = $TenantId
    }

    $executeDeviceCode = {
        if ($connectCommand.Parameters.ContainsKey("UseDeviceAuthentication")) {
            Connect-MgGraph @connectParams -UseDeviceAuthentication
        }
        elseif ($connectCommand.Parameters.ContainsKey("UseDeviceCode")) {
            Connect-MgGraph @connectParams -UseDeviceCode
        }
        else {
            Write-Warn "Parametro de Device Code nao encontrado. Usando autenticacao interativa padrao."
            Connect-MgGraph @connectParams
        }
    }

    try {
        if ($LoginMode -eq "Browser") {
            Connect-MgGraph @connectParams
        }
        elif ($LoginMode -eq "DeviceCode") {
            & $executeDeviceCode
        }
        else { # Auto
            try {
                Connect-MgGraph @connectParams
            }
            catch {
                Write-Warn "Nao foi possivel abrir o login no navegador. Tentando login por codigo de dispositivo."
                & $executeDeviceCode
            }
        }
    }
    catch {
        $errorMessage = $_.ToString()
        if ($null -ne $_.Exception) {
            if ($null -ne $_.Exception.Message) {
                $errorMessage += " " + $_.Exception.Message
            }
        }
        if ($errorMessage -like "*timed out*") {
            Write-Err "O tempo limite de autenticacao expirou. Execute o script novamente e conclua o login do Microsoft Graph em ate 120 segundos."
            exit 1
        }
        else {
            throw $_
        }
    }
    
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Nao foi possivel recuperar o TenantId do contexto ativo do Microsoft Graph."
    }
    
    if (-not [string]::IsNullOrEmpty($TenantId) -and $ctx.TenantId -ne $TenantId) {
        Write-Err "O Tenant autenticado ($($ctx.TenantId)) e diferente do TenantId informado ($TenantId)."
        exit 1
    }
    
    $tenantName = "Desconhecido"
    $primaryDomain = "Desconhecido"
    try {
        Write-Info "Consultando metadados do Tenant..."
        $orgResponse = Invoke-MgGraphRequest -Method GET -Uri "v1.0/organization" -ErrorAction Stop
        if ($orgResponse -and $orgResponse.value -and $orgResponse.value.Count -gt 0) {
            $org = $orgResponse.value[0]
            $tenantName = $org.displayName
            $primaryDomainObj = $org.verifiedDomains | Where-Object { $_.isDefault -eq $true -or $_['isDefault'] -eq $true }
            if ($primaryDomainObj) {
                $primaryDomain = $primaryDomainObj.name
            } else {
                $primaryDomain = $org.verifiedDomains[0].name
            }
        }
    }
    catch {
        Write-Warn "Nao foi possivel consultar os detalhes do Tenant via API Graph: $($_.Exception.Message)"
    }
    
    if ([string]::IsNullOrEmpty($TenantId)) {
        Write-Host ""
        Write-Host "Inquilino (Tenant) Detectado:" -ForegroundColor Cyan
        Write-Host "  ID do Tenant:   $($ctx.TenantId)" -ForegroundColor Cyan
        Write-Host "  Nome do Tenant: $tenantName" -ForegroundColor Cyan
        Write-Host "  Dominio Padrao: $primaryDomain" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Voce confirma que deseja realizar o onboarding neste Tenant? (S/N): " -NoNewline
        $confirm = Read-Host
        if ($confirm -notmatch "^[sSyY]") {
            Write-Err "Onboarding cancelado pelo usuario."
            exit 1
        }
    } else {
        Write-Info "Tenant Autenticado:"
        Write-Info "  ID do Tenant:   $($ctx.TenantId)"
        Write-Info "  Nome do Tenant: $tenantName"
        Write-Info "  Dominio Padrao: $primaryDomain"
    }
    
    return [pscustomobject]@{
        TenantId      = $ctx.TenantId
        TenantName    = $tenantName
        PrimaryDomain = $primaryDomain
    }
}

# ==========================================
# 5. PERMISSOES E CONFIGURACAO DO ENTIDADE
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
        throw "Nao foi possivel localizar o Service Principal do Microsoft Graph."
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
            throw "A permissao (AppRole) '$val' nao foi encontrada no Service Principal do Microsoft Graph."
        }
        $appRoleMap[$val] = $role.Id
    }
    return $appRoleMap
}

# ==========================================
# 6. CRIACAO E RENOVACAO DO APLICATIVO
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
    
    Write-Info "Verificando se um App Registration com o nome '$DisplayName' ja existe..."
    $existingApps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    $app = $null
    if ($existingApps) {
        Write-Warn "Um App Registration com o nome '$DisplayName' ja existe no seu inquilino."
        Write-Host "Deseja reutilizar o App Registration existente? (S/N): " -NoNewline
        $choice = Read-Host
        
        if ($choice -match "^[sSyY]") {
            $app = $existingApps[0]
            Write-Info "Reutilizando o App Registration existente. Application ID (ClientId): $($app.AppId)"
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
        Write-Info "Atualizando as permissoes configuradas no App Registration..."
        $updateParams = @{
            RequiredResourceAccess = $requiredResourceAccess
        }
        Update-MgApplication -ApplicationId $app.Id @updateParams -ErrorAction Stop
        $app = Get-MgApplication -ApplicationId $app.Id -ErrorAction Stop
    } else {
        Write-Info "Criando um novo App Registration..."
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
    
    Write-Info "Garantindo que o Service Principal correspondente exista..."
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Info "Criando o Service Principal..."
        $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        Write-Info "Service Principal criado com sucesso."
    } else {
        Write-Info "Service Principal ja existe."
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
    Write-Info "Adicionando um novo client secret..."
    $secretDisplayName = "vulneri-finops-secret"
    $endDate = (Get-Date).AddMonths($SecretMonths)
    
    $passwordCred = @{
        displayName  = $secretDisplayName
        endDateTime  = $endDate.ToUniversalTime()
    }
    
    $secretObj = Add-MgApplicationPassword -ApplicationId $ApplicationObjectId -PasswordCredential $passwordCred -ErrorAction Stop
    $clientSecret = $secretObj.SecretText
    
    if (-not $clientSecret) {
        throw "Falha ao gerar o Client Secret (retornou valor vazio)."
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
# 7. VALIDACAO E RENOVACAO
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
    Write-Info "Iniciando a validacao do registro do aplicativo ClientId: $ClientId..."
    
    $permissionsExpected = Get-PermissionsForMode -Mode $Mode
    $checkedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    try {
        Write-Info "Localizando o App Registration..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration com o ClientId '$ClientId' nao foi encontrado."
        }
        
        Write-Info "Localizando o Service Principal..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $sp) {
            throw "Service Principal correspondente ao ClientId '$ClientId' nao foi encontrado."
        }
        
        $graphSp = Get-GraphServicePrincipal
        $graphAppId = "00000003-0000-0000-c000-000000000000"
        
        $idToNameMap = @{}
        foreach ($role in $graphSp.AppRoles) {
            $idToNameMap[$role.Id.ToString()] = $role.Value
        }
        
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
        
        $permissionsGranted = @()
        Write-Info "Buscando permissoes com consentimento administrativo..."
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
        
        $validationStatus = "ready"
        if ($permissionsMissing.Count -gt 0) {
            $validationStatus = "missing_permissions"
            Write-Warn "Validacao: Algumas permissoes obrigatorias nao estao configuradas no RequiredResourceAccess."
        }
        elseif ($permissionsPendingConsent.Count -gt 0) {
            $validationStatus = "pending_admin_consent"
            Write-Warn "Validacao: Permissoes configuradas estao aguardando consentimento administrativo."
        }
        else {
            Write-Info "Validacao: Tudo pronto! Todas as permissoes obrigatorias foram configuradas e consentidas."
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
        Write-Err "Erro durante a validacao: $($_.Exception.Message)"
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
    Write-Info "Iniciando a renovacao do Client Secret para o ClientId: $ClientId..."
    
    try {
        Write-Info "Localizando o App Registration no inquilino..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration com o ClientId '$ClientId' nao foi encontrado."
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
# 8. PROCESSAMENTO DA SAIDA JSON / .ENV
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
        Write-Warn "O arquivo '.env' ja existe no diretorio atual e sera sobrescrito."
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
    Write-Warn "AVISO DE SEGURANCA: Arquivo .env gerado em: $envPath"
    Write-Warn "Use -WriteEnvFile apenas para testes ou ambientes controlados."
    Write-Warn "Este arquivo contem credenciais altamente confidenciais."
    Write-Warn "Nunca envie este arquivo para repositorios Git ou compartilhe-o."
    Write-Warn "============================================================"
}

# ==========================================
# 9. FLUXO PRINCIPAL DE EXECUCAO
# ==========================================

try {
    Write-Host "== Vulneri Microsoft 365 Onboarding ==" -ForegroundColor Cyan
    Write-Info "Este script configura os acessos necessarios do Microsoft 365 para auditoria de FinOps."
    Write-Info "Privilegios de Administrador local nao sao necessarios; no entanto, privilegios de Administrador de Tenant sao requeridos."
    
    if ($ValidateOnly) {
        Write-Info "Modo Selecionado: Validacao de Permissoes (-ValidateOnly)"
    } elseif ($RenewSecret) {
        Write-Info "Modo Selecionado: Renovacao de Credenciais (-RenewSecret)"
    } else {
        Write-Info "Modo Selecionado: $Mode"
        if ($Mode -eq "Starter") {
            Write-Info "Este modo solicita apenas permissoes de leitura para inventario de licencas e relatorios de uso."
        } else {
            Write-Info "Este modo solicita permissoes adicionais para politicas de seguranca, logs de auditoria e identidades."
        }
    }
    Write-Host ""
    
    # 1. Carregar dependencias
    Ensure-GraphModules
    
    # 2. Conectar e obter metadados
    $tenantDetails = Connect-M365Tenant -TenantId $TenantId -LoginMode $LoginMode
    
    if ($ValidateOnly) {
        # Executar validacao
        $valOutput = Test-VulneriM365Onboarding -TenantId $tenantDetails.TenantId -ClientId $ClientId -Mode $Mode
        
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "RESULTADO DA VALIDACAO (JSON):" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $valOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $tenantDetails.TenantId -ClientId $ClientId -Mode $Mode
        }
    }
    elseif ($RenewSecret) {
        # Executar renovacao
        $renewOutput = Renew-VulneriM365Secret -TenantId $tenantDetails.TenantId -ClientId $ClientId -SecretMonths $SecretMonths
        
        Write-Host ""
        Write-Warn "Recomendacao: Remova as secrets antigas no console do Azure/Entra apenas apos confirmar o funcionamento da nova credencial na plataforma Vulneri."
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "COPIE E COLE O JSON ABAIXO NA PLATAFORMA VULNERI:" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $renewOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $tenantDetails.TenantId -ClientId $ClientId -ClientSecret $renewOutput.m365ClientSecret -SecretExpiresAt $renewOutput.secretExpiresAt -Mode $Mode
        }
    }
    else {
        # Executar fluxo completo de criacao
        $permissions = Get-PermissionsForMode -Mode $Mode
        
        Write-Info "Carregando informacoes do Service Principal do Microsoft Graph..."
        $graphSp = Get-GraphServicePrincipal
        $appRoleMap = Resolve-GraphAppRoles -GraphSp $graphSp -Permissions $permissions
        
        $appResult = New-VulneriM365Application -DisplayName $DisplayName -AppRoleMap $appRoleMap -Permissions $permissions
        $app = $appResult.Application
        $sp = $appResult.ServicePrincipal
        
        # Criar a secret, mantendo apenas em memoria
        $secretResult = New-VulneriM365Secret -ApplicationObjectId $app.Id -SecretMonths $SecretMonths
        
        # Tentar aplicar consentimento automatico (AppRoleAssignments)
        $automaticConsentFailed = $false
        
        Write-Info "Buscando permissoes ja concedidas para evitar duplicidade..."
        $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
        
        foreach ($permission in $permissions) {
            $roleId = $appRoleMap[$permission]
            
            $alreadyGranted = $existingAssignments | Where-Object {
                $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $roleId
            }
            if ($alreadyGranted) {
                Write-Info "A permissao '$permission' ja estava concedida."
                continue
            }
            
            Write-Info "Tentando conceder a permissao '$permission' de forma automatica..."
            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $roleId -ErrorAction Stop | Out-Null
                Write-Info "Permissao '$permission' concedida com sucesso."
            }
            catch {
                $err = $_.ToString()
                if ($null -ne $_.Exception -and $null -ne $_.Exception.Message) {
                    $err += " " + $_.Exception.Message
                }
                
                if ($err -like "*already exists*" -or $err -like "*PermissionAlreadyExists*") {
                    Write-Info "A permissao '$permission' ja havia sido concedida."
                } else {
                    Write-Warn "Nao foi possivel conceder a permissao '$permission' de forma automatica."
                    $automaticConsentFailed = $true
                }
            }
        }
        
        $consentUrl = Get-AdminConsentUrl -TenantId $tenantDetails.TenantId -ClientId $app.AppId
        
        # Loop interativo de validacao de consentimento de administrador
        $validated = $false
        while (-not $validated) {
            if ($automaticConsentFailed) {
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Yellow
                Write-Host "ACAO REQUERIDA: CONCEDER CONSENTIMENTO DO ADMINISTRADOR" -ForegroundColor Yellow
                Write-Host "============================================================" -ForegroundColor Yellow
                Write-Host "O aplicativo foi criado no seu tenant Microsoft 365,"
                Write-Host "mas nao pode ser autorizado de forma automatica devido a limitacoes de privilegio do seu usuario atual."
                Write-Host ""
                Write-Host "Um administrador com privilegios do tenant precisa conceder o consentimento das permissoes."
                Write-Host "Quem pode fazer isso:"
                Write-Host "- Administrador Global"
                Write-Host "- Administrador de Funcao Privilegiada"
                Write-Host ""
                Write-Host "Abra a URL abaixo no seu navegador, faca o login com uma conta administrativa,"
                Write-Host "revise as permissoes solicitadas e clique em Aceitar."
                Write-Host "Em seguida, retorne a este terminal e pressione ENTER para validar."
                Write-Host ""
                Write-Host "Importante:"
                Write-Host "O Client Secret foi gerado em memoria, mas so sera exibido apos"
                Write-Host "a validacao do consentimento. Se fechar este terminal antes de validar,"
                Write-Host "voce devera gerar uma nova chave executando o script com -RenewSecret."
                Write-Host "============================================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "URL de Consentimento do Administrador:" -ForegroundColor Yellow
                Write-Host "  $consentUrl" -ForegroundColor Cyan
                Write-Host ""
                
                try {
                    Write-Info "Tentando abrir a URL no seu navegador automaticamente..."
                    if ($IsWindows) {
                        Start-Process $consentUrl
                    } elseif ($IsMacOS) {
                        Start-Process "open" $consentUrl
                    } elseif ($IsLinux) {
                        Start-Process "xdg-open" $consentUrl
                    } else {
                        Start-Process $consentUrl
                    }
                }
                catch {
                    Write-Warn "Nao foi possivel abrir o navegador automaticamente: $($_.Exception.Message)"
                    Write-Warn "Por favor, copie e cole a URL acima manualmente no seu navegador."
                }
                
                Write-Host ""
                Write-Host "Pressione ENTER apos conceder o consentimento no navegador..." -NoNewline
                $null = Read-Host
            }
            
            # Rodar verificacao de validacao automatica
            $valResult = Test-VulneriM365Onboarding -TenantId $tenantDetails.TenantId -ClientId $app.AppId -Mode $Mode
            
            if ($valResult.validationStatus -eq "ready") {
                $validated = $true
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host "SUCESSO: Onboarding validado com sucesso!" -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host ""
                
                # Resumo
                Write-Host "== RESUMO DA INSTALACAO ==" -ForegroundColor Cyan
                Write-Host "ID do Tenant Microsoft 365:   $($tenantDetails.TenantId)"
                Write-Host "Nome do Tenant:               $($tenantDetails.TenantName)"
                Write-Host "Dominio Padrao:               $($tenantDetails.PrimaryDomain)"
                Write-Host "ID do Cliente (ClientId):     $($app.AppId)"
                Write-Host "Secret do Cliente (Secret):   [Exibido apenas no JSON abaixo]"
                Write-Warn "Salve a chave secreta agora. Ela nao sera exibida novamente."
                Write-Host ""
                Write-Info "Copie o JSON abaixo e cadastre-o na plataforma Vulneri."
                Write-Host ""
                
                $createdAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                $creationOutput = @{
                    provider             = "m365"
                    mode                 = $Mode.ToLower()
                    m365TenantId         = $tenantDetails.TenantId
                    m365TenantName       = $tenantDetails.TenantName
                    m365PrimaryDomain    = $tenantDetails.PrimaryDomain
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
                    Write-OptionalEnvFile -TenantId $tenantDetails.TenantId -ClientId $app.AppId -ClientSecret $secretResult.SecretText -SecretExpiresAt $secretResult.ExpiresAt -Mode $Mode
                }
            } else {
                $automaticConsentFailed = $true # Forcar menu manual no loop de repeticao
                Write-Host ""
                Write-Err "A validacao falhou ou esta incompleta (Status: $($valResult.validationStatus))"
                if ($valResult.permissionsPendingConsent.Count -gt 0) {
                    Write-Err "Permissoes configuradas aguardando consentimento: $($valResult.permissionsPendingConsent -join ', ')"
                }
                if ($valResult.permissionsMissing.Count -gt 0) {
                    Write-Err "Permissoes ausentes na configuracao do aplicativo: $($valResult.permissionsMissing -join ', ')"
                }
                Write-Host ""
                
                Write-Host "Deseja tentar a validacao novamente agora? (S/N): " -NoNewline
                $choice = Read-Host
                
                if ($choice -notmatch "^[sSyY]") {
                    Write-Warn "Onboarding suspenso. O App Registration foi criado, mas as credenciais nao foram validadas."
                    Write-Warn "Para validar novamente mais tarde, execute:"
                    Write-Warn "  ./m365_onboarding.ps1 -ValidateOnly -ClientId $($app.AppId) -TenantId $($tenantDetails.TenantId) -Mode $Mode"
                    Write-Warn "Se voce fechou este terminal e precisa gerar uma nova secret, execute:"
                    Write-Warn "  ./m365_onboarding.ps1 -RenewSecret -ClientId $($app.AppId) -TenantId $($tenantDetails.TenantId)"
                    break
                }
            }
        }
    }
}
catch {
    Write-Err "Ocorreu um erro inesperado durante a execucao: $($_.Exception.Message)"
    exit 1
}
