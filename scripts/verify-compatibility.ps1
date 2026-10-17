param(
    [Parameter(Mandatory = $true)][string] $BaselineJar,
    [Parameter(Mandatory = $true)][string] $Java8Home,
    [Parameter(Mandatory = $true)][string] $ModernJavaHome,
    [string] $CandidateJar,
    [string] $DependencyClasspath,
    [string] $DependencyClasspathFile,
    [string] $Maven = 'mvn'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectDirectory = Split-Path $PSScriptRoot -Parent

function Resolve-ExistingFile([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file does not exist: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).ProviderPath
}

function Invoke-Checked([string] $Executable, [string[]] $Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Executable $($Arguments -join ' ')"
    }
}

Push-Location $projectDirectory
try {
    $baseline = Resolve-ExistingFile $BaselineJar
    if (-not $CandidateJar) {
        [xml] $projectPom = Get-Content -LiteralPath pom.xml -Raw
        $CandidateJar = Join-Path $projectDirectory "target/utils-mail-dkim-$($projectPom.project.version).jar"
    }
    $candidate = Resolve-ExistingFile $CandidateJar
    if ($baseline -eq $candidate) {
        throw 'BaselineJar and CandidateJar must be different files'
    }
    $java8 = Resolve-ExistingFile (Join-Path $Java8Home 'bin/java.exe')
    $javac8 = Resolve-ExistingFile (Join-Path $Java8Home 'bin/javac.exe')
    $javap8 = Resolve-ExistingFile (Join-Path $Java8Home 'bin/javap.exe')
    $modernJava = Resolve-ExistingFile (Join-Path $ModernJavaHome 'bin/java.exe')
    $modernJavac = Resolve-ExistingFile (Join-Path $ModernJavaHome 'bin/javac.exe')
    $source = Resolve-ExistingFile 'src/test/compatibility/LegacyClient.java'
    $resources = (Resolve-Path -LiteralPath 'src/test/resources').ProviderPath
    if ($DependencyClasspath -and $DependencyClasspathFile) {
        throw 'Supply DependencyClasspath or DependencyClasspathFile, not both'
    }

    # Each invocation starts with empty class directories, without deleting prior
    # results or touching the normal Maven build outputs and baseline API capture.
    $outputDirectory = Join-Path $projectDirectory ('target/compatibility/' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    if ($DependencyClasspathFile) {
        $DependencyClasspath = (Get-Content -LiteralPath (Resolve-ExistingFile $DependencyClasspathFile) -Raw).Trim()
    } elseif (-not $DependencyClasspath) {
        $classpathFile = Join-Path $outputDirectory 'runtime-classpath.txt'
        Invoke-Checked $Maven @('dependency:build-classpath', '-DincludeScope=runtime', "-Dmdep.outputFile=$classpathFile")
        $DependencyClasspath = (Get-Content -LiteralPath $classpathFile -Raw).Trim()
    }
    $dependencyFiles = @($DependencyClasspath.Split([IO.Path]::PathSeparator) | ForEach-Object {
        $dependencyFile = Resolve-ExistingFile $_
        if ([IO.Path]::GetFileName($dependencyFile) -like 'utils-mail-dkim-*.jar') {
            throw 'Runtime dependency classpath must not include another utils-mail-dkim JAR'
        }
        $dependencyFile
    })
    $dependencies = $dependencyFiles -join [IO.Path]::PathSeparator
    $baselineClasspath = $baseline + [IO.Path]::PathSeparator + $dependencies
    $candidateClasspath = $candidate + [IO.Path]::PathSeparator + $dependencies

    $publicTypes = @('Canonicalization', 'DkimAcceptanceException', 'DkimException', 'DkimMessage',
        'DkimSigner', 'DkimSigningException', 'DomainKey', 'DomainKeyUtil', 'KeyPairType', 'SigningAlgorithm') |
        ForEach-Object { 'org.simplejavamail.utils.mail.dkim.' + $_ }
    $baselineApi = @(Invoke-Checked $javap8 (@('-protected', '-classpath', $baselineClasspath) + $publicTypes))
    $candidateApi = @(Invoke-Checked $javap8 (@('-protected', '-classpath', $candidateClasspath) + $publicTypes))
    $baselineApi | Set-Content -LiteralPath (Join-Path $outputDirectory 'baseline-api.txt') -Encoding UTF8
    $candidateApi | Set-Content -LiteralPath (Join-Path $outputDirectory 'candidate-api.txt') -Encoding UTF8
    # Method-level synchronized is an implementation modifier, not a source or
    # binary API member. DNS lookup locking deliberately moved inside the method.
    $baselineDeclarations = @($baselineApi | Where-Object { $_ -match '^\s*(public|protected) ' } |
        ForEach-Object { $_.Trim().Replace('synchronized ', '') } | Sort-Object)
    $candidateDeclarations = @($candidateApi | Where-Object { $_ -match '^\s*(public|protected) ' } |
        ForEach-Object { $_.Trim().Replace('synchronized ', '') } | Sort-Object)
    $apiChanges = @(Compare-Object $baselineDeclarations $candidateDeclarations)
    if ($apiChanges.Count -ne 0) {
        $apiChanges | Format-Table | Out-String | Write-Host
        throw "Public/protected API declarations differ; inspect $outputDirectory"
    }

    $legacyClasses = New-Item -ItemType Directory -Path (Join-Path $outputDirectory 'legacy-classes')
    $candidateClasses8 = New-Item -ItemType Directory -Path (Join-Path $outputDirectory 'candidate-source-java8')
    $candidateClassesModern = New-Item -ItemType Directory -Path (Join-Path $outputDirectory 'candidate-source-modern')
    Invoke-Checked $javac8 @('-encoding', 'UTF-8', '-classpath', $baselineClasspath, '-d', $legacyClasses.FullName, $source)
    Invoke-Checked $javac8 @('-encoding', 'UTF-8', '-classpath', $candidateClasspath, '-d', $candidateClasses8.FullName, $source)
    Invoke-Checked $modernJavac @('--release', '8', '-encoding', 'UTF-8', '-classpath', $candidateClasspath,
        '-d', $candidateClassesModern.FullName, $source)

    $expectedOutput = $null
    foreach ($runtime in @($java8, $modernJava)) {
        foreach ($library in @($baselineClasspath, $candidateClasspath)) {
            $runtimeClasspath = $legacyClasses.FullName + [IO.Path]::PathSeparator + $library
            $actualOutput = @(Invoke-Checked $runtime @('-classpath', $runtimeClasspath, 'LegacyClient', $resources)) -join "`n"
            if ($null -eq $expectedOutput) {
                $expectedOutput = $actualOutput
            } elseif ($actualOutput -ne $expectedOutput) {
                throw "Legacy client behavior/output changed for $runtime using $library"
            }
        }
    }
    Write-Host $expectedOutput
    Write-Host 'Public/protected API, source compatibility, and unchanged legacy classes passed on both JDKs.'
    Write-Host "Compatibility evidence: $outputDirectory"
} finally {
    Pop-Location
}
