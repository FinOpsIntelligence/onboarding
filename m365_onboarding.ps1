<#
.SYNOPSIS
  Script de Onboarding do Microsoft 365 para Vulneri FinOps M365.
  
.DESCRIPTION
  Este script automatiza o processo de onboarding de um tenant do Microsoft 365 para a Vulneri FinOps:
  - Cria ou atualiza um App Registration & Service Principal no Entra ID
  - Configura RequiredResourceAccess para permissões de modo "Starter" ou "Expert"
  - Tenta conceder o consentimento de administrador de forma automática
  - Gera uma chave secreta (client secret) com expiração customizada
  - Gera a URL de consentimento caso falhe a concessão automática
  - Executa testes de validação na configuração final das permissões
  - Renova segredos de aplicativos existentes
  - Valida permissões de registros existentes

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
    [switch]$WriteEnvFile
)

# ==========================================
# 1. FUNÇÕES DE LOGGING (Português)
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
# 2. VALIDAÇÃO DE PARÂMETROS INICIAIS
# ==========================================

if ($ValidateOnly -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "O parâmetro -ClientId é obrigatório quando -ValidateOnly é utilizado."
    exit 1
}

if ($RenewSecret -and [string]::IsNullOrEmpty($ClientId)) {
    Write-Err "O parâmetro -ClientId é obrigatório quando -RenewSecret é utilizado."
    exit 1
}

# ==========================================
# 3. VERIFICAÇÃO DE DEPENDÊNCIAS DO GRAPH
# ==========================================

function Ensure-GraphModules {
    Write-Info "Verificando dependências do PowerShell..."
    
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        try {
            Write-Info "Garantindo NuGet package provider..."
            Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch {
            Write-Err "Falha ao instalar o NuGet Package Provider - $($_.Exception.Message)"
            Write-Err "Por favor, execute o script em uma versão do PowerShell 7+ ou certifique-se de executar como um usuário com privilégios para instalar módulos em CurrentUser."
        }
    }

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
    )

    foreach ($module in $requiredModules) {
        Write-Info "Verificando módulo $module..."
        $installed = Get-Module -ListAvailable -Name $module
        if (-not $installed) {
            Write-Info "Instalando módulo $module..."
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Info "Módulo $module instalado com sucesso."
            }
            catch {
                Write-Err "Falha ao instalar o módulo $module - $($_.Exception.Message)"
                Write-Err "Por favor, execute manualmente: Install-Module $module -Scope CurrentUser -Force -AllowClobber"
                exit 1
            }
        }

        Write-Info "Carregando módulo $module..."
        try {
            Import-Module $module -ErrorAction Stop
            Write-Info "Módulo $module carregado com sucesso."
        }
        catch {
            Write-Err "Falha ao carregar o módulo $module - $($_.Exception.Message)"
            exit 1
        }
    }

    # Validar cmdlets obrigatórios
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

    Write-Info "Validando cmdlets obrigatórios..."
    $missingCmdlets = @()
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) {
            $missingCmdlets += $cmdlet
        }
    }

    if ($missingCmdlets.Count -gt 0) {
        Write-Err "Os seguintes cmdlets obrigatórios estão ausentes: $($missingCmdlets -join ', ')"
        Write-Err "Por favor, reinstale os módulos executando:"
        Write-Err "  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber"
        Write-Err "  Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber"
        exit 1
    }
    Write-Info "Todos os cmdlets obrigatórios foram validados com sucesso."
}

# ==========================================
# 4. AUTENTICAÇÃO E METADADOS DO TENANT
# ==========================================

function Connect-M365Tenant {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    $scopes = @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.Read.All")
    Write-Info "Conectando ao Microsoft Graph com escopos delegados necessários..."
    
    Write-Host ""
    Write-Host "************************************************************" -ForegroundColor Yellow
    Write-Host "               LOGIN MICROSOFT 365 NECESSÁRIO               " -ForegroundColor White -BackgroundColor Red
    Write-Host "************************************************************" -ForegroundColor Yellow
    Write-Host "Para se autenticar, você DEVE abrir a página de login no navegador" -ForegroundColor Cyan
    Write-Host "e inserir o código de dispositivo temporário que a Microsoft exibirá" -ForegroundColor Cyan
    Write-Host "no terminal abaixo." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Procure a mensagem da Microsoft iniciando com:" -ForegroundColor White
    Write-Host "  'Para entrar, use um navegador da Web para abrir a página...'" -ForegroundColor Green
    Write-Host "  (Ou 'To sign in, use a web browser to open the page...')" -ForegroundColor Green
    Write-Host "************************************************************" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
        $connectParams = @{
            Scopes       = $scopes
            ContextScope = "Process"
            ErrorAction  = "Stop"
        }

        if (-not [string]::IsNullOrEmpty($TenantId)) {
            $connectParams["TenantId"] = $TenantId
        }

        if ($connectCommand.Parameters.ContainsKey("UseDeviceCode")) {
            $connectParams["UseDeviceCode"] = $true
        }
        elseif ($connectCommand.Parameters.ContainsKey("UseDeviceAuthentication")) {
            $connectParams["UseDeviceAuthentication"] = $true
        }
        else {
            Write-Warn "Parâmetro de Device Code não encontrado. Usando autenticação interativa padrão."
        }

        Connect-MgGraph @connectParams
    }
    catch {
        $errorMessage = $_.ToString()
        if ($null -ne $_.Exception) {
            if ($null -ne $_.Exception.Message) {
                $errorMessage += " " + $_.Exception.Message
            }
        }
        if ($errorMessage -like "*timed out*") {
            Write-Err "O tempo limite de autenticação expirou. Execute o script novamente e conclua o login do Microsoft Graph em até 120 segundos."
            exit 1
        }
        else {
            throw $_
        }
    }
    
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw "Não foi possível recuperar o TenantId do contexto ativo do Microsoft Graph."
    }
    
    if (-not [string]::IsNullOrEmpty($TenantId) -and $ctx.TenantId -ne $TenantId) {
        Write-Err "O Tenant autenticado ($($ctx.TenantId)) é diferente do TenantId informado ($TenantId)."
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
        Write-Warn "Não foi possível consultar os detalhes do Tenant via API Graph: $($_.Exception.Message)"
    }
    
    if ([string]::IsNullOrEmpty($TenantId)) {
        Write-Host ""
        Write-Host "Inquilino (Tenant) Detectado:" -ForegroundColor Cyan
        Write-Host "  ID do Tenant:   $($ctx.TenantId)" -ForegroundColor Cyan
        Write-Host "  Nome do Tenant: $tenantName" -ForegroundColor Cyan
        Write-Host "  Domínio Padrão: $primaryDomain" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Você confirma que deseja realizar o onboarding neste Tenant? (S/N): " -NoNewline
        $confirm = Read-Host
        if ($confirm -notmatch "^[sSyY]") {
            Write-Err "Onboarding cancelado pelo usuário."
            exit 1
        }
    } else {
        Write-Info "Tenant Autenticado:"
        Write-Info "  ID do Tenant:   $($ctx.TenantId)"
        Write-Info "  Nome do Tenant: $tenantName"
        Write-Info "  Domínio Padrão: $primaryDomain"
    }
    
    return [pscustomobject]@{
        TenantId      = $ctx.TenantId
        TenantName    = $tenantName
        PrimaryDomain = $primaryDomain
    }
}

# ==========================================
# 5. PERMISSÕES E CONFIGURAÇÃO DO ENTIDADE
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
# 6. CRIAÇÃO E RENOVAÇÃO DO APLICATIVO
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
    
    Write-Info "Verificando se um App Registration com o nome '$DisplayName' já existe..."
    $existingApps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    $app = $null
    if ($existingApps) {
        Write-Warn "Um App Registration com o nome '$DisplayName' já existe no seu inquilino."
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
        Write-Info "Atualizando as permissões configuradas no App Registration..."
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
# 7. VALIDAÇÃO E RENOVAÇÃO
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
    Write-Info "Iniciando a validação do registro do aplicativo ClientId: $ClientId..."
    
    $permissionsExpected = Get-PermissionsForMode -Mode $Mode
    $checkedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    try {
        Write-Info "Localizando o App Registration..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration com o ClientId '$ClientId' não foi encontrado."
        }
        
        Write-Info "Localizando o Service Principal..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $sp) {
            throw "Service Principal correspondente ao ClientId '$ClientId' não foi encontrado."
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
            Write-Warn "Validação: Algumas permissões obrigatórias não estão configuradas no RequiredResourceAccess."
        }
        elseif ($permissionsPendingConsent.Count -gt 0) {
            $validationStatus = "pending_admin_consent"
            Write-Warn "Validação: Permissões configuradas estão aguardando consentimento administrativo."
        }
        else {
            Write-Info "Validação: Tudo pronto! Todas as permissões obrigatórias foram configuradas e consentidas."
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
        Write-Info "Localizando o App Registration no inquilino..."
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
        if (-not $app) {
            throw "App Registration com o ClientId '$ClientId' não foi encontrado."
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
# 8. PROCESSAMENTO DA SAÍDA JSON / .ENV
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
    Write-Warn "Nunca envie este arquivo para repositórios Git ou compartilhe-o."
    Write-Warn "============================================================"
}

# ==========================================
# 9. FLUXO PRINCIPAL DE EXECUÇÃO
# ==========================================

try {
    Write-Host "== Vulneri Microsoft 365 Onboarding ==" -ForegroundColor Cyan
    Write-Info "Este script configura os acessos necessários do Microsoft 365 para auditoria de FinOps."
    Write-Info "Privilégios de Administrador local não são necessários; no entanto, privilégios de Administrador de Tenant são requeridos."
    
    if ($ValidateOnly) {
        Write-Info "Modo Selecionado: Validação de Permissões (-ValidateOnly)"
    } elseif ($RenewSecret) {
        Write-Info "Modo Selecionado: Renovação de Credenciais (-RenewSecret)"
    } else {
        Write-Info "Modo Selecionado: $Mode"
        if ($Mode -eq "Starter") {
            Write-Info "Este modo solicita apenas permissões de leitura para inventário de licenças e relatórios de uso."
        } else {
            Write-Info "Este modo solicita permissões adicionais para políticas de segurança, logs de auditoria e identidades."
        }
    }
    Write-Host ""
    
    # 1. Carregar dependências
    Ensure-GraphModules
    
    # 2. Conectar e obter metadados
    $tenantDetails = Connect-M365Tenant -TenantId $TenantId
    
    if ($ValidateOnly) {
        # Executar validação
        $valOutput = Test-VulneriM365Onboarding -TenantId $tenantDetails.TenantId -ClientId $ClientId -Mode $Mode
        
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "RESULTADO DA VALIDAÇÃO (JSON):" -ForegroundColor Cyan
        $json = ConvertTo-SafeJsonOutput -Payload $valOutput
        Write-Host $json -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        
        if ($WriteEnvFile) {
            Write-OptionalEnvFile -TenantId $tenantDetails.TenantId -ClientId $ClientId -Mode $Mode
        }
    }
    elseif ($RenewSecret) {
        # Executar renovação
        $renewOutput = Renew-VulneriM365Secret -TenantId $tenantDetails.TenantId -ClientId $ClientId -SecretMonths $SecretMonths
        
        Write-Host ""
        Write-Warn "Recomendação: Remova as secrets antigas no console do Azure/Entra apenas após confirmar o funcionamento da nova credencial na plataforma Vulneri."
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
        # Executar fluxo completo de criação
        $permissions = Get-PermissionsForMode -Mode $Mode
        
        Write-Info "Carregando informações do Service Principal do Microsoft Graph..."
        $graphSp = Get-GraphServicePrincipal
        $appRoleMap = Resolve-GraphAppRoles -GraphSp $graphSp -Permissions $permissions
        
        $appResult = New-VulneriM365Application -DisplayName $DisplayName -AppRoleMap $appRoleMap -Permissions $permissions
        $app = $appResult.Application
        $sp = $appResult.ServicePrincipal
        
        # Criar a secret, mantendo apenas em memória
        $secretResult = New-VulneriM365Secret -ApplicationObjectId $app.Id -SecretMonths $SecretMonths
        
        # Tentar aplicar consentimento automático (AppRoleAssignments)
        $automaticConsentFailed = $false
        
        Write-Info "Buscando permissões já concedidas para evitar duplicidade..."
        $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
        
        foreach ($permission in $permissions) {
            $roleId = $appRoleMap[$permission]
            
            $alreadyGranted = $existingAssignments | Where-Object {
                $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $roleId
            }
            if ($alreadyGranted) {
                Write-Info "A permissão '$permission' já estava concedida."
                continue
            }
            
            Write-Info "Tentando conceder a permissão '$permission' de forma automática..."
            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $roleId -ErrorAction Stop | Out-Null
                Write-Info "Permissão '$permission' concedida com sucesso."
            }
            catch {
                $err = $_.ToString()
                if ($null -ne $_.Exception -and $null -ne $_.Exception.Message) {
                    $err += " " + $_.Exception.Message
                }
                
                if ($err -like "*already exists*" -or $err -like "*PermissionAlreadyExists*") {
                    Write-Info "A permissão '$permission' já havia sido concedida."
                } else {
                    Write-Warn "Não foi possível conceder a permissão '$permission' de forma automática."
                    $automaticConsentFailed = $true
                }
            }
        }
        
        $consentUrl = Get-AdminConsentUrl -TenantId $tenantDetails.TenantId -ClientId $app.AppId
        
        # Loop interativo de validação de consentimento de administrador
        $validated = $false
        while (-not $validated) {
            if ($automaticConsentFailed) {
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Yellow
                Write-Host "AÇÃO REQUERIDA: CONCEDER CONSENTIMENTO DO ADMINISTRADOR" -ForegroundColor Yellow
                Write-Host "============================================================" -ForegroundColor Yellow
                Write-Host "O aplicativo foi criado no seu tenant Microsoft 365,"
                Write-Host "mas não pôde ser autorizado de forma automática devido a limitações de privilégio do seu usuário atual."
                Write-Host ""
                Write-Host "Um administrador com privilégios do tenant precisa conceder o consentimento das permissões."
                Write-Host "Quem pode fazer isso:"
                Write-Host "- Administrador Global"
                Write-Host "- Administrador de Função Privilegiada"
                Write-Host ""
                Write-Host "Abra a URL abaixo no seu navegador, faça o login com uma conta administrativa,"
                Write-Host "revise as permissões solicitadas e clique em Aceitar."
                Write-Host "Em seguida, retorne a este terminal e pressione ENTER para validar."
                Write-Host ""
                Write-Host "Importante:"
                Write-Host "O Client Secret foi gerado em memória, mas só será exibido após"
                Write-Host "a validação do consentimento. Se fechar este terminal antes de validar,"
                Write-Host "você deverá gerar uma nova chave executando o script com -RenewSecret."
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
                    Write-Warn "Não foi possível abrir o navegador automaticamente: $($_.Exception.Message)"
                    Write-Warn "Por favor, copie e cole a URL acima manualmente no seu navegador."
                }
                
                Write-Host ""
                Write-Host "Pressione ENTER após conceder o consentimento no navegador..." -NoNewline
                $null = Read-Host
            }
            
            # Rodar verificação de validação automática
            $valResult = Test-VulneriM365Onboarding -TenantId $tenantDetails.TenantId -ClientId $app.AppId -Mode $Mode
            
            if ($valResult.validationStatus -eq "ready") {
                $validated = $true
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host "SUCESSO: Onboarding validado com sucesso!" -ForegroundColor Green
                Write-Host "============================================================" -ForegroundColor Green
                Write-Host ""
                
                # Resumo
                Write-Host "== RESUMO DA INSTALAÇÃO ==" -ForegroundColor Cyan
                Write-Host "ID do Tenant Microsoft 365:   $($tenantDetails.TenantId)"
                Write-Host "Nome do Tenant:               $($tenantDetails.TenantName)"
                Write-Host "Domínio Padrão:               $($tenantDetails.PrimaryDomain)"
                Write-Host "ID do Cliente (ClientId):     $($app.AppId)"
                Write-Host "Secret do Cliente (Secret):   [Exibido apenas no JSON abaixo]"
                Write-Warn "Salve a chave secreta agora. Ela não será exibida novamente."
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
                $automaticConsentFailed = $true # Forçar menu manual no loop de repetição
                Write-Host ""
                Write-Err "A validação falhou ou está incompleta (Status: $($valResult.validationStatus))"
                if ($valResult.permissionsPendingConsent.Count -gt 0) {
                    Write-Err "Permissões configuradas aguardando consentimento: $($valResult.permissionsPendingConsent -join ', ')"
                }
                if ($valResult.permissionsMissing.Count -gt 0) {
                    Write-Err "Permissões ausentes na configuração do aplicativo: $($valResult.permissionsMissing -join ', ')"
                }
                Write-Host ""
                
                Write-Host "Deseja tentar a validação novamente agora? (S/N): " -NoNewline
                $choice = Read-Host
                
                if ($choice -notmatch "^[sSyY]") {
                    Write-Warn "Onboarding suspenso. O App Registration foi criado, mas as credenciais não foram validadas."
                    Write-Warn "Para validar novamente mais tarde, execute:"
                    Write-Warn "  ./m365_onboarding.ps1 -ValidateOnly -ClientId $($app.AppId) -TenantId $($tenantDetails.TenantId) -Mode $Mode"
                    Write-Warn "Se você fechou este terminal e precisa gerar uma nova secret, execute:"
                    Write-Warn "  ./m365_onboarding.ps1 -RenewSecret -ClientId $($app.AppId) -TenantId $($tenantDetails.TenantId)"
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
