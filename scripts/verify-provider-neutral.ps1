param(
    [Parameter(Mandatory = $true)][string] $Java8Home,
    [Parameter(Mandatory = $true)][string] $ModernJavaHome,
    [string] $CandidateJar,
    [string] $DependencyClasspathFile
)
$ErrorActionPreference = 'Stop'
$dkimProjectRoot = Split-Path $PSScriptRoot -Parent
function Invoke-DkimChecked([string] $Executable, [string[]] $Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Consumer command failed: $Executable" }
}
Push-Location $dkimProjectRoot
try {
    if (-not $CandidateJar) {
        [xml] $dkimProjectPom = Get-Content -LiteralPath pom.xml -Raw
        $CandidateJar = Join-Path $dkimProjectRoot "target/utils-mail-dkim-$($dkimProjectPom.project.version).jar"
    }
    $CandidateJar = (Resolve-Path -LiteralPath $CandidateJar).ProviderPath
    $dkimConsumerRoot = Join-Path $dkimProjectRoot ('target/provider-neutral/' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dkimConsumerRoot | Out-Null
    if (-not $DependencyClasspathFile) {
        $DependencyClasspathFile = Join-Path $dkimConsumerRoot 'dependencies.txt'
        Invoke-DkimChecked 'mvn' @('dependency:build-classpath', '-DincludeScope=runtime', "-Dmdep.outputFile=$DependencyClasspathFile")
    }
    $dkimDependencyEntries = (Get-Content -LiteralPath $DependencyClasspathFile -Raw).Trim().Split([IO.Path]::PathSeparator)
    $dkimDependencies = @($dkimDependencyEntries | Where-Object { [IO.Path]::GetFileName($_) -notlike 'angus-*' })
    $dkimRuntimePath = (@($CandidateJar) + $dkimDependencies) -join [IO.Path]::PathSeparator
    $dkimSourceRoot = Join-Path $dkimProjectRoot 'src/test/java/org/simplejavamail/dkim/consumer'
    $dkimSources = @(Get-ChildItem -LiteralPath $dkimSourceRoot -Filter '*.java' | ForEach-Object FullName)
    $dkimClasspathClasses = Join-Path $dkimConsumerRoot 'classpath'
    $dkimModuleClasses = Join-Path $dkimConsumerRoot 'jpms'
    New-Item -ItemType Directory -Path $dkimClasspathClasses,$dkimModuleClasses | Out-Null
    Invoke-DkimChecked (Join-Path $Java8Home 'bin/javac.exe') (@('-encoding','UTF-8','-classpath',$dkimRuntimePath,'-d',$dkimClasspathClasses) + $dkimSources)
    foreach ($dkimRuntimeHome in @($Java8Home,$ModernJavaHome)) {
        Invoke-DkimChecked (Join-Path $dkimRuntimeHome 'bin/java.exe') @('-classpath',($dkimClasspathClasses + [IO.Path]::PathSeparator + $dkimRuntimePath),'org.simplejavamail.dkim.consumer.ByteSigningConsumer')
    }
    $dkimDescriptor = Join-Path $dkimProjectRoot 'src/test/provider-neutral-jpms/module-info.java'
    Invoke-DkimChecked (Join-Path $ModernJavaHome 'bin/javac.exe') (@('--release','11','-encoding','UTF-8','--module-path',$dkimRuntimePath,'-d',$dkimModuleClasses,$dkimDescriptor) + $dkimSources)
    Invoke-DkimChecked (Join-Path $ModernJavaHome 'bin/java.exe') @('--module-path',($dkimModuleClasses + [IO.Path]::PathSeparator + $dkimRuntimePath),'--module','org.simplejavamail.dkim.consumer/org.simplejavamail.dkim.consumer.ByteSigningConsumer')
    Write-Output 'Angus-free classpath and JPMS consumers completed against the packaged candidate.'
} finally {
    Pop-Location
}
