# ============================================================
#  VBA L°(k3r.ps1 — Proteção de Projeto VBA via edição binária
#  Implementa MS-OVBA 2.4.3 (Data Encryption) + 2.4.4 (Hash)
#  Interface WPF com drag & drop e log em tempo real
# ============================================================
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# ─── Algoritmos MS-OVBA ──────────────────────────────────────────────────────
# Todos como ScriptBlock para reusar no Runspace

$OVBA_EncryptData = {
    param([string]$projectCLSID, [byte[]]$data, [uint32]$dataLength)
    # MS-OVBA 2.4.3.2 Encryption
    # ProjKey = soma dos bytes do CLSID
    $projKey = [byte]0
    foreach ($ch in [System.Text.Encoding]::ASCII.GetBytes($projectCLSID)) {
        $projKey = [byte](($projKey + $ch) -band 0xFF)
    }
    $seed = [byte](Get-Random -Minimum 1 -Maximum 255)
    $versionEnc  = [byte]($seed -bxor 2)           # Version = 2
    $projKeyEnc  = [byte]($seed -bxor $projKey)

    $enc1 = $projKeyEnc
    $enc2 = $versionEnc
    $unc1 = $projKey

    $result = [System.Collections.Generic.List[byte]]::new()
    $result.Add($seed)
    $result.Add($versionEnc)
    $result.Add($projKeyEnc)

    # IgnoredEnc  (0 a 3 bytes)
    $ignoredLen = ($seed -band 6) / 2
    for ($i = 0; $i -lt $ignoredLen; $i++) {
        $tmp = [byte](Get-Random -Minimum 0 -Maximum 255)
        $byteEnc = [byte](($tmp -bxor ($enc2 + $unc1)) -band 0xFF)
        $result.Add($byteEnc)
        $enc2 = $enc1; $enc1 = $byteEnc; $unc1 = $tmp
    }

    # DataLengthEnc (4 bytes, little-endian)
    $lenBytes = [BitConverter]::GetBytes([uint32]$dataLength)
    foreach ($b in $lenBytes) {
        $byteEnc = [byte](($b -bxor ($enc2 + $unc1)) -band 0xFF)
        $result.Add($byteEnc)
        $enc2 = $enc1; $enc1 = $byteEnc; $unc1 = $b
    }

    # DataEnc
    foreach ($db in $data) {
        $byteEnc = [byte](($db -bxor ($enc2 + $unc1)) -band 0xFF)
        $result.Add($byteEnc)
        $enc2 = $enc1; $enc1 = $byteEnc; $unc1 = $db
    }

    return $result.ToArray()
}

$OVBA_EncodeNulls = {
    param([byte[]]$inputBytes)
    $grbit = 0
    $encoded = [System.Collections.Generic.List[byte]]::new()
    for ($i = 0; $i -lt $inputBytes.Length; $i++) {
        if ($inputBytes[$i] -eq 0x00) {
            $encoded.Add(0x01)
            # bit = 0 (FALSE) – já é o padrão, grbit não precisa mudar
        } else {
            $encoded.Add($inputBytes[$i])
            $grbit = $grbit -bor (1 -shl $i)   # bit = 1 (TRUE)
        }
    }
    return [PSCustomObject]@{ Grbit=$grbit; Encoded=$encoded.ToArray() }
}

$OVBA_BuildHashData = {
    param([string]$password)
    # MS-OVBA 2.4.4
    # 1. Gera key aleatória (4 bytes)
    $key = [byte[]](1..4 | ForEach-Object { Get-Random -Minimum 1 -Maximum 255 })

    # 2. Password em MBCS (Windows-1252)
    $pwdBytes = [System.Text.Encoding]::GetEncoding(1252).GetBytes($password)

    # 3. SHA1(password || key)
    $toHash = [byte[]]($pwdBytes + $key)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $hash = $sha1.ComputeHash($toHash)   # 20 bytes

    # 4. Encode Nulls em Key e Hash
    $keyEnc  = & $OVBA_EncodeNulls $key
    $hashEnc = & $OVBA_EncodeNulls $hash

    # 5. Monta a estrutura  (29 bytes total)
    #    1 byte Reserved (0xFF)
    #    1 byte: GrbitKey (4 bits) + GrbitHashNull high nibble (4 bits)
    #    2 bytes: GrbitHashNull low 16 bits
    #    4 bytes: KeyNoNulls
    #   20 bytes: PasswordHashNoNulls
    #    1 byte: Terminator (0x00)
    $grbitKey  = [int]($keyEnc.Grbit  -band 0x0F)
    $grbitHash = [int]($hashEnc.Grbit -band 0xFFFFF)

    # Pack: byte1 = reserved 0xFF
    # byte2 = GrbitKey[3:0] | GrbitHash[19:16]
    # byte3 = GrbitHash[15:8]
    # byte4 = GrbitHash[7:0]
    $b2 = [byte](($grbitKey -shl 4) -bor (($grbitHash -shr 16) -band 0x0F))
    $b3 = [byte](($grbitHash -shr 8) -band 0xFF)
    $b4 = [byte]($grbitHash -band 0xFF)

    $struct = [byte[]](@(0xFF, $b2, $b3, $b4) + $keyEnc.Encoded + $hashEnc.Encoded + @(0x00))
    return $struct   # 29 bytes
}

$OVBA_EncryptCMG = {
    param([string]$clsid, [uint32]$state)
    # CMG = ProjectProtectionState
    # state=1 → fUserProtected
    $data = [BitConverter]::GetBytes($state)   # 4 bytes LE
    return & $OVBA_EncryptData $clsid $data 4
}

$OVBA_EncryptDPB = {
    param([string]$clsid, [string]$password)
    $hashData = & $OVBA_BuildHashData $password   # 29 bytes
    return & $OVBA_EncryptData $clsid $hashData 29
}

$OVBA_EncryptGC = {
    param([string]$clsid, [bool]$visible)
    # GC = ProjectVisibilityState: 0 = hidden, 1 = visible
    if ($visible) { $data = [byte[]]@(0x01) } else { $data = [byte[]]@(0x00) }
    return & $OVBA_EncryptData $clsid $data 1
}

# ─── Lógica de proteção binária ──────────────────────────────────────────────

function Protect-VBABinary {
    param(
        [string]$path,
        [string]$password,
        [bool]$hideProject,
        [bool]$backup
    )

    $log = [System.Collections.Generic.List[PSCustomObject]]::new()
    function L([string]$m, [string]$c="n") { $log.Add([PSCustomObject]@{msg=$m;cor=$c}) }

    # ── Backup
    if ($backup) {
        $ts  = Get-Date -Format "yyyyMMdd_HHmmss"
        $bak = [System.IO.Path]::ChangeExtension($path, $null).TrimEnd('.') + "_backup_$ts" + [System.IO.Path]::GetExtension($path)
        Copy-Item $path $bak -Force
        $bakSz = (Get-Item $bak).Length
        L "backup criado: $([System.IO.Path]::GetFileName($bak))" "ok"
        L "backup — $bakSz bytes" "bytes"
    }

    # ── Bifurcação para .xls (OLE Binary) ──────────────────────────────────────
    $ext = [System.IO.Path]::GetExtension($path).ToLower()
    if ($ext -eq ".xls" -or $ext -eq ".xlt") {
        L "formato legacy .xls detectado (OLE Binary)" "info"
        L "processando arquivo como bloco unico" "info"
        
        $raw = [System.IO.File]::ReadAllBytes($path)
        
        # Extração do CLSID (a mesma lógica funciona pois o texto está em ASCII no OLE)
        $projText = [System.Text.Encoding]::GetEncoding(1252).GetString($raw)
        $clsidMatch = [regex]::Match($projText, 'ID="\{([^}]+)\}"')
        $currentCLSID = if ($clsidMatch.Success) { "{$($clsidMatch.Groups[1].Value)}" } else { "{00000000-0000-0000-0000-000000000000}" }
        L "CLSID atual: $currentCLSID" "info"

        $hasCMG = $projText -match 'CMG="([^"]+)"'
        $hasDPB = $projText -match 'DPB="([^"]+)"'
        $hasGC  = $projText -match 'GC="([^"]+)"'

        if (-not ($hasCMG -and $hasDPB -and $hasGC)) {
            L "CMG/DPB/GC não encontrados — arquivo pode não ter VBA ou já estar em formato incompatível" "err"
            return $log
        }

        L "estrutura CMG/DPB/GC localizada ✓" "ok"
        L "calculando hash SHA1 da senha..." "info"

        $newCLSID = "{00000000-0000-0000-0000-000000000000}"

        # Gera CMG, DPB, GC usando as funções que já existem no topo do script
        $cmgBytes = & $OVBA_EncryptCMG $newCLSID ([uint32]1)
        $cmgHex   = ($cmgBytes | ForEach-Object { $_.ToString("X2") }) -join ""
        
        $dpbBytes = & $OVBA_EncryptDPB $newCLSID $password
        $dpbHex   = ($dpbBytes | ForEach-Object { $_.ToString("X2") }) -join ""
        
        $gcBytes = & $OVBA_EncryptGC $newCLSID (-not $hideProject)
        $gcHex   = ($gcBytes | ForEach-Object { $_.ToString("X2") }) -join ""

        L "injetando proteção via byte-level injection" "info"

        # A mesma lógica de injeção de tamanho fixo, aplicada no arquivo inteiro
        $newRaw = $raw
        $propertiesToReplace = @(
            @{ Name="CMG"; NewValue=$cmgHex },
            @{ Name="DPB"; NewValue=$dpbHex },
            @{ Name="GC";  NewValue=$gcHex }
        )

        foreach ($prop in $propertiesToReplace) {
            $searchPattern = [System.Text.Encoding]::ASCII.GetBytes("$($prop.Name)=""")
            $quoteByte = [System.Text.Encoding]::ASCII.GetBytes('"')[0]
            
            $startIdx = -1
            for ($i = 0; $i -lt $newRaw.Length - $searchPattern.Length; $i++) {
                $match = $true
                for ($j = 0; $j -lt $searchPattern.Length; $j++) {
                    if ($newRaw[$i+$j] -ne $searchPattern[$j]) { $match = $false; break }
                }
                if ($match) { $startIdx = $i + $searchPattern.Length; break }
            }

            if ($startIdx -ne -1) {
                $endIdx = $startIdx
                while ($endIdx -lt $newRaw.Length -and $newRaw[$endIdx] -ne $quoteByte) { $endIdx++ }

                $oldLength = $endIdx - $startIdx
                $newValueBytes = [System.Text.Encoding]::ASCII.GetBytes($prop.NewValue)
                
                $paddedValue = [byte[]]::new($oldLength)
                if ($newValueBytes.Length -ge $oldLength) {
                    [Array]::Copy($newValueBytes, 0, $paddedValue, 0, $oldLength)
                } else {
                    [Array]::Copy($newValueBytes, 0, $paddedValue, 0, $newValueBytes.Length)
                }

                [Array]::Copy($paddedValue, 0, $newRaw, $startIdx, $oldLength)
                L "$($prop.Name) injetado com sucesso ✓" "ok"
            } else {
                L "$($prop.Name) não encontrado no stream binário" "err"
            }
        }

        # Salva direto por cima do .xls
        [System.IO.File]::WriteAllBytes($path, $newRaw)
        $finalSz = (Get-Item $path).Length
        
        L "─────────────────────────────────────" "info"
        L "arquivo final: $finalSz bytes" "bytes"
        L "proteção VBA aplicada com sucesso ✓" "ok"
        
        # Retorna cedo! Não executa a lógica de ZIP abaixo.
        return $log 
    }
    # ── Fim da bifurcação .xls ─────────────────────────────────────────────────

    $origSz = (Get-Item $path).Length
    L "arquivo original: $origSz bytes" "bytes"
    L "descompactando container ZIP..." "info"

    $tempDir = [System.IO.Path]::Combine($env:TEMP, [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($path, $tempDir)

    $vbaBin = Join-Path $tempDir "xl\vbaProject.bin"
    if (-not (Test-Path $vbaBin)) {
        L "vbaProject.bin não encontrado — arquivo sem código VBA" "err"
        Remove-Item $tempDir -Recurse -Force
        return $log
    }

    $binSz = (Get-Item $vbaBin).Length
    L "vbaProject.bin — $binSz bytes" "bytes"
    L "lendo stream PROJECT (texto OLE)..." "info"

    # Lê o arquivo como texto (está dentro de um CFB mas a parte que nos interessa
    # está como texto ASCII no stream PROJECT — buscamos no binário bruto)
    $raw = [System.IO.File]::ReadAllBytes($vbaBin)

    # Encontra "ID=" no binário para extrair o CLSID atual
    $idPattern = [System.Text.Encoding]::ASCII.GetBytes('ID="{')
    $idIdx = -1
    for ($i = 0; $i -lt $raw.Length - 50; $i++) {
        $match = $true
        for ($j = 0; $j -lt $idPattern.Length; $j++) {
            if ($raw[$i+$j] -ne $idPattern[$j]) { $match = $false; break }
        }
        if ($match) { $idIdx = $i + $idPattern.Length - 1; break }
    }

    if ($idIdx -lt 0) {
        L "stream PROJECT não encontrado no binário" "err"
        Remove-Item $tempDir -Recurse -Force
        return $log
    }

    # Extrai o CLSID completo: procura "ID=" e pega até o próximo "
    $textStart = $idIdx - 4  # volta ao I de ID
    # Varre em busca da região de texto PROJECT
    $projText = ""
    $enc = [System.Text.Encoding]::GetEncoding(1252)
    for ($start = [Math]::Max(0, $idIdx-4); $start -lt $raw.Length - 200; $start++) {
        $chunk = $enc.GetString($raw, $start, [Math]::Min(4096, $raw.Length - $start))
        if ($chunk.Contains('CMG=') -or $chunk.Contains('ID="')) {
            # Vai um pouco para trás para pegar o ID completo
            $projText = $enc.GetString($raw, [Math]::Max(0,$start-200), [Math]::Min(8192, $raw.Length - [Math]::Max(0,$start-200)))
            break
        }
    }

    # Extrai CLSID atual
    $clsidMatch = [regex]::Match($projText, 'ID="\{([^}]+)\}"')
    $currentCLSID = if ($clsidMatch.Success) { "{$($clsidMatch.Groups[1].Value)}" } else { "{00000000-0000-0000-0000-000000000000}" }
    L "CLSID atual: $currentCLSID" "info"

    # Verifica se CMG/DPB/GC existem
    $hasCMG = $projText -match 'CMG="([^"]+)"'
    $hasDPB = $projText -match 'DPB="([^"]+)"'
    $hasGC  = $projText -match 'GC="([^"]+)"'

    if (-not ($hasCMG -and $hasDPB -and $hasGC)) {
        L "CMG/DPB/GC não encontrados — arquivo pode não ter VBA ou já estar em formato incompatível" "err"
        Remove-Item $tempDir -Recurse -Force
        return $log
    }

    L "estrutura CMG/DPB/GC localizada ✓" "ok"
    L "calculando hash SHA1 da senha..." "info"

    # ── Gera novo CLSID nulo (obrigatório para password hash)
    $newCLSID = "{00000000-0000-0000-0000-000000000000}"

    # ── Gera CMG (proteção ativada: fUserProtected = bit0 = 1)
    $cmgBytes = & $OVBA_EncryptCMG $newCLSID ([uint32]1)
    $cmgHex   = ($cmgBytes | ForEach-Object { $_.ToString("X2") }) -join ""
    L "CMG gerado: $cmgHex" "bytes"

    # ── Gera DPB (hash da senha)
    $dpbBytes = & $OVBA_EncryptDPB $newCLSID $password
    $dpbHex   = ($dpbBytes | ForEach-Object { $_.ToString("X2") }) -join ""
    L "DPB gerado: $($dpbHex.Substring(0, [Math]::Min(32,$dpbHex.Length)))..." "bytes"

    # ── Gera GC (visibilidade: hidden se hideProject)
    $gcBytes = & $OVBA_EncryptGC $newCLSID (-not $hideProject)
    $gcHex   = ($gcBytes | ForEach-Object { $_.ToString("X2") }) -join ""
    L "GC gerado: $gcHex" "bytes"

    # ── Reconstrói o bloco PROJECT substituindo via Bytes (sem converter para String)
    L "injetando proteção via byte-level injection" "info"

    # Função auxiliar para substituir bytes preservando o tamanho exato do arquivo
    # Isso impede que o Excel delete o vbaProject.bin por inconsistência de tamanho
    $newRaw = $raw # Começa com o array original

    $propertiesToReplace = @(
        @{ Name="CMG"; NewValue=$cmgHex },
        @{ Name="DPB"; NewValue=$dpbHex },
        @{ Name="GC";  NewValue=$gcHex }
    )

    foreach ($prop in $propertiesToReplace) {
        # Padrão de busca: ex: CMG="
        $searchPattern = [System.Text.Encoding]::ASCII.GetBytes("$($prop.Name)=""")
        $quoteByte = [System.Text.Encoding]::ASCII.GetBytes('"')[0]
        
        # 1. Encontra o início da propriedade
        $startIdx = -1
        for ($i = 0; $i -lt $newRaw.Length - $searchPattern.Length; $i++) {
            $match = $true
            for ($j = 0; $j -lt $searchPattern.Length; $j++) {
                if ($newRaw[$i+$j] -ne $searchPattern[$j]) { $match = $false; break }
            }
            if ($match) { $startIdx = $i + $searchPattern.Length; break }
        }

        if ($startIdx -ne -1) {
            # 2. Encontra a aspa de fechamento
            $endIdx = $startIdx
            while ($endIdx -lt $newRaw.Length -and $newRaw[$endIdx] -ne $quoteByte) {
                $endIdx++
            }

            $oldLength = $endIdx - $startIdx
            $newValueBytes = [System.Text.Encoding]::ASCII.GetBytes($prop.NewValue)
            $newLength = $newValueBytes.Length

            L "$($prop.Name) encontrado: offset 0x$($startIdx.ToString('X')), tamanho original: $oldLength bytes" "bytes"

            # 3. Prepara o novo valor com padding (para manter o tamanho idêntico)
            $paddedValue = [byte[]]::new($oldLength)
            if ($newLength -ge $oldLength) {
                # Se o novo for maior, trunca para caber no espaço original
                [Array]::Copy($newValueBytes, 0, $paddedValue, 0, $oldLength)
                L "$($prop.Name) truncado para caber no espaço original" "info"
            } else {
                # Se o novo for menor, copia e deixa o resto como 0x00 (Null)
                [Array]::Copy($newValueBytes, 0, $paddedValue, 0, $newLength)
                L "$($prop.Name) preenchido com padding nulo (0x00)" "info"
            }

            # 4. Injeta os bytes diretamente no array
            [Array]::Copy($paddedValue, 0, $newRaw, $startIdx, $oldLength)
            L "$($prop.Name) injetado com sucesso ✓" "ok"
        } else {
            L "$($prop.Name) não encontrado no stream binário" "err"
        }
    }

    # Salva o arquivo
    [System.IO.File]::WriteAllBytes($vbaBin, $newRaw)
    $newBinSz = (Get-Item $vbaBin).Length
    L "vbaProject.bin reescrito — $newBinSz bytes" "bytes"

    # ── Recompacta
    L "recompactando arquivo Excel..." "info"
    $outPath = $path
    if (Test-Path $outPath) { Remove-Item $outPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $tempDir, $outPath,
        [System.IO.Compression.CompressionLevel]::Optimal, $false)

    $finalSz = (Get-Item $outPath).Length
    Remove-Item $tempDir -Recurse -Force

    L "temp limpo" "info"
    L "─────────────────────────────────────" "info"
    L "arquivo final: $finalSz bytes" "bytes"
    L "proteção VBA aplicada com sucesso ✓" "ok"
    L "senha definida: $('*' * $password.Length)" "ok"
    if ($hideProject) { L "projeto ocultado na árvore VBA" "ok" }

    return $log
}

# ─── Interface WPF ───────────────────────────────────────────────────────────

 $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="VBA L°(k3r" Height="640" Width="560"
    WindowStartupLocation="CenterScreen"
    Background="#0A0A0A"
    ResizeMode="CanMinimize"
    FontFamily="Consolas">
  <Window.Resources>
    <Style x:Key="FlatBtn" TargetType="Button">
      <Setter Property="Background" Value="#00C896"/>
      <Setter Property="Foreground" Value="#0A0A0A"/>
      <Setter Property="FontFamily" Value="Consolas"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="2" Padding="16,10">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#00FFBC"/></Trigger>
              <Trigger Property="IsPressed"   Value="True"><Setter Property="Background" Value="#009E76"/></Trigger>
              <Trigger Property="IsEnabled"   Value="False">
                <Setter Property="Background" Value="#1A1A1A"/>
                <Setter Property="Foreground" Value="#555"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="GhostBtn" TargetType="Button" BasedOn="{StaticResource FlatBtn}">
      <Setter Property="Background" Value="#141414"/>
      <Setter Property="Foreground" Value="#AAAAAA"/>
      <Setter Property="FontSize"   Value="11"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#1E1E1E"/>
          <Setter Property="Foreground" Value="#DDDDDD"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background"       Value="#111"/>
      <Setter Property="Foreground"       Value="#00C896"/>
      <Setter Property="BorderBrush"      Value="#333333"/>
      <Setter Property="BorderThickness"  Value="1"/>
      <Setter Property="Padding"          Value="8,7"/>
      <Setter Property="FontFamily"       Value="Consolas"/>
      <Setter Property="FontSize"         Value="13"/>
      <Setter Property="CaretBrush"       Value="#00C896"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderBrush" Value="#AAAAAA"/>
      <Setter Property="Foreground" Value="#CCCCCC"/>
    </Style>
  </Window.Resources>

  <Grid Margin="26">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header (Textos mais claros) -->
    <StackPanel Grid.Row="0" Margin="0,0,0,22">
      <TextBlock Text="VBA L°(k3r" FontSize="21" FontWeight="Bold"
                 Foreground="#00C896" FontFamily="Consolas"/>
      <TextBlock Text="binary-level excel vba project lock  ·  ms-ovba 2.4.3/2.4.4  ·  by diegoac"
                 FontSize="10" Foreground="#AAAAAA" Margin="2,3,0,0"/>
    </StackPanel>

    <!-- Drop Zone (Borda e textos mais visíveis) -->
    <Border Grid.Row="1" x:Name="DropZone" Height="108" CornerRadius="3"
            BorderThickness="1" BorderBrush="#333333" Background="#0E0E0E"
            Margin="0,0,0,12" AllowDrop="True" Cursor="Hand">
      <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
        <TextBlock x:Name="DropIcon" Text="⬇" FontSize="26"
                   Foreground="#555555" HorizontalAlignment="Center"/>
        <TextBlock x:Name="DropLabel"
                   Text="arraste o arquivo  .xlsm  /  .xlsb  /  .xls"
                   FontSize="11" Foreground="#AAAAAC"
                   HorizontalAlignment="Center" Margin="0,7,0,0"/>
        <TextBlock x:Name="DropFile" Text="" FontSize="10"
                   Foreground="#00C896" HorizontalAlignment="Center"
                   Margin="0,5,0,0" TextWrapping="Wrap" MaxWidth="460"/>
      </StackPanel>
    </Border>

    <!-- Browse -->
    <Button Grid.Row="2" x:Name="BtnBrowse" Content="[ selecionar arquivo ]"
            Style="{StaticResource GhostBtn}" HorizontalAlignment="Left"
            Margin="0,0,0,22"/>

    <!-- Senhas (Labels mais claros) -->
    <Grid Grid.Row="3" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="14"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Text="SENHA" FontSize="9" Foreground="#999999"
                   Margin="0,0,0,5"/>
        <PasswordBox x:Name="TxtSenha" Height="36"/>
      </StackPanel>
      <StackPanel Grid.Column="2">
        <TextBlock Text="CONFIRMAR SENHA" FontSize="9" Foreground="#999999"
                   Margin="0,0,0,5"/>
        <PasswordBox x:Name="TxtConfirm" Height="36"/>
      </StackPanel>
    </Grid>

    <!-- Opções (Texto mais claro) -->
    <StackPanel Grid.Row="4" Orientation="Horizontal" Margin="0,4,0,18">
      <CheckBox x:Name="ChkHide" IsChecked="True" VerticalContentAlignment="Center" Background="Transparent">
        <TextBlock Text="ocultar projeto na árvore VBA" Foreground="#AAAAAA" FontSize="11"/>
      </CheckBox>
      <CheckBox x:Name="ChkBackup" IsChecked="True" Margin="22,0,0,0" VerticalContentAlignment="Center" Background="Transparent">
        <TextBlock Text="criar backup antes de proteger" Foreground="#AAAAAA" FontSize="11"/>
      </CheckBox>
    </StackPanel>

    <!-- Log Terminal (Bordas e texto padrão mais claros) -->
    <Border Grid.Row="5" BorderBrush="#333333" BorderThickness="1"
            Background="#060606" CornerRadius="2" Margin="0,0,0,16">
      <TextBox x:Name="LogBox" FontFamily="Consolas" FontSize="11"
               Foreground="#AAAAAA" Background="#060606" BorderThickness="0"
               Padding="12,10" TextWrapping="Wrap" IsReadOnly="True"
               VerticalScrollBarVisibility="Auto"
               Text="// aguardando operação...&#x0a;"
               AcceptsReturn="True" IsUndoEnabled="False"/>
    </Border>

    <!-- Botão Proteger -->
    <Button Grid.Row="6" x:Name="BtnProteger"
            Content="▶  PROTEGER PROJETO VBA"
            Style="{StaticResource FlatBtn}"
            Height="44" IsEnabled="False"/>
  </Grid>
</Window>
"@

[xml]$XamlDoc = $xaml
$reader  = [System.Xml.XmlNodeReader]::new($XamlDoc)
$window  = [Windows.Markup.XamlReader]::Load($reader)

$DropZone    = $window.FindName("DropZone")
$DropLabel   = $window.FindName("DropLabel")
$DropIcon    = $window.FindName("DropIcon")
$DropFile    = $window.FindName("DropFile")
$BtnBrowse   = $window.FindName("BtnBrowse")
$TxtSenha    = $window.FindName("TxtSenha")
$TxtConfirm  = $window.FindName("TxtConfirm")
$ChkHide     = $window.FindName("ChkHide")
$ChkBackup   = $window.FindName("ChkBackup")
$LogBox      = $window.FindName("LogBox")
$LogScroll   = $window.FindName("LogScroll")
$BtnProteger = $window.FindName("BtnProteger")

$script:ArquivoSelecionado = ""

# ── Helpers UI ───────────────────────────────────────────────

function AppendLog([string]$msg, [string]$cor) {
    $ts = Get-Date -Format "HH:mm:ss.fff"
    $prefix = switch ($cor) {
        "ok"    { "[+]" }; "err"  { "[!]" }
        "info"  { "[~]" }; "bytes"{ "[B]" }
        default { "[>]" }
    }
    # Cores com muito mais contraste contra o fundo #060606
    $colorHex = switch ($cor) {
        "ok"    { "#00C896" }  # Verde principal (mantido)
        "err"   { "#FF5555" }  # Vermelho erro (mantido)
        "bytes" { "#5599FF" }  # Azul info byte (mantido)
        "info"  { "#AAAAAA" }  # Cinza bem claro (ANTES #888888)
        default { "#AAAAAC" }  # Cinza quase branco (ANTES #555555)
    }
    $window.Dispatcher.Invoke([Action]{
        $run = [System.Windows.Documents.Run]::new("$ts  $prefix  $msg`n")
        $run.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.ColorConverter]::ConvertFromString($colorHex))
        # LogBox é TextBlock simples — usamos InLines se houver, caso contrário apendamos texto
        # Como WPF TextBlock não suporta multi-color facilmente em XAML puro,
        # usamos uma RichTextBox alternativa ou simplesmente Text puro com cor por estado
        $LogBox.Text += "$ts  $prefix  $msg`n"
        $LogBox.ScrollToEnd()
    })
}

function SetArquivo([string]$path) {
    if (-not ($path -match '\.(xlsm|xlsb|xls|xlsx)$')) {
        AppendLog "formato inválido — use .xlsm, .xlsb ou .xls" "err"; return
    }
    $script:ArquivoSelecionado = $path
    $nome  = [System.IO.Path]::GetFileName($path)
    $bytes = (Get-Item $path).Length
    $kb    = [math]::Round($bytes / 1KB, 2)
    $window.Dispatcher.Invoke([Action]{
        $DropFile.Text            = $path
        $DropIcon.Text            = "✓"
        $DropIcon.Foreground      = [System.Windows.Media.Brushes]::MediumAquamarine
        $DropLabel.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.ColorConverter]::ConvertFromString("#AAAAAA"))
        $BtnProteger.IsEnabled    = $true
    })
    AppendLog "arquivo: $nome" "ok"
    AppendLog "tamanho: $bytes bytes  ($kb KB)" "bytes"
    AppendLog "caminho: $path" "info"
}

# ── Drag & Drop ───────────────────────────────────────────────
$DropZone.Add_DragOver({
    param($s, $e)
    if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) {
        $e.Effects = [Windows.DragDropEffects]::Copy
        $DropZone.BorderBrush = [System.Windows.Media.Brushes]::MediumAquamarine
    }
    $e.Handled = $true
})
$DropZone.Add_DragLeave({
    $DropZone.BorderBrush = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.ColorConverter]::ConvertFromString("#1E1E1E"))
})
$DropZone.Add_Drop({
    param($s, $e)
    $DropZone.BorderBrush = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.ColorConverter]::ConvertFromString("#1E1E1E"))
    $files = $e.Data.GetData([Windows.DataFormats]::FileDrop)
    if ($files.Count -gt 0) { SetArquivo $files[0] }
})
$DropZone.Add_MouseLeftButtonDown({
    $dlg = [Microsoft.Win32.OpenFileDialog]::new()
    $dlg.Filter = "Excel com Macro|*.xlsm;*.xlsb;*.xls;*.xlsx"
    $dlg.Title  = "Selecionar arquivo Excel"
    if ($dlg.ShowDialog()) { SetArquivo $dlg.FileName }
})
$BtnBrowse.Add_Click({
    $dlg = [Microsoft.Win32.OpenFileDialog]::new()
    $dlg.Filter = "Excel com Macro|*.xlsm;*.xlsb;*.xls;*.xlsx"
    $dlg.Title  = "Selecionar arquivo Excel"
    if ($dlg.ShowDialog()) { SetArquivo $dlg.FileName }
})

# ── Botão Proteger ────────────────────────────────────────────
$BtnProteger.Add_Click({
    $path    = $script:ArquivoSelecionado
    $senha   = $TxtSenha.Password
    $confirm = $TxtConfirm.Password
    $hide    = [bool]$ChkHide.IsChecked
    $bkp     = [bool]$ChkBackup.IsChecked

    if ([string]::IsNullOrWhiteSpace($senha))  { AppendLog "informe uma senha" "err"; return }
    if ($senha -ne $confirm)                    { AppendLog "as senhas nao coincidem" "err"; return }
    if (-not (Test-Path $path))                 { AppendLog "arquivo nao encontrado" "err"; return }

    $LogBox.Text = ""
    $BtnProteger.IsEnabled = $false
    [System.Windows.Forms.Application]::DoEvents()

    AppendLog "iniciando protecao binaria MS-OVBA..." "info"
    AppendLog "algoritmo: Data Encryption (2.4.3) + SHA1 Hash (2.4.4)" "info"
    AppendLog "─────────────────────────────────────" "info"
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $results = Protect-VBABinary -path $path -password $senha -hideProject $hide -backup $bkp
        foreach ($r in $results) {
            AppendLog $r.msg $r.cor
            [System.Windows.Forms.Application]::DoEvents()
        }
    } catch {
        AppendLog "ERRO: $_" "err"
    }

    $BtnProteger.IsEnabled = $true
})

$window.ShowDialog() | Out-Null