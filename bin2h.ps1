param(
    [Parameter(Mandatory, Position = 0)]
    [string]$InputFile,
    [Parameter(Mandatory, Position = 1)]
    [string]$OutputFile
)

((Get-Content -Encoding byte $InputFile | % { [int32]$_ }) -join ",") >$OutputFile
