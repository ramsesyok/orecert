param([string]$Path = 'coverage.out', [int]$Minimum = 90)
$ErrorActionPreference = 'Stop'
$covered = 0L
$statements = 0L
$blocks = @{}
foreach ($line in (Get-Content -LiteralPath $Path | Select-Object -Skip 1)) {
    $fields = $line -split '\s+'
    if ($fields.Count -ne 3) { throw "不正なカバレッジ行: $line" }
    $count = [long]$fields[1]
    $key = $fields[0]
    # coverpkgによるテスト実行単位ごとの重複ブロックを統合します。
    if (!$blocks.ContainsKey($key)) { $blocks[$key] = @{ Count = $count; Covered = $false } }
    if ($blocks[$key].Count -ne $count) { throw "文の数が不一致です: $key" }
    if ([long]$fields[2] -gt 0) { $blocks[$key].Covered = $true }
}
foreach ($block in $blocks.Values) {
    $statements += $block.Count
    if ($block.Covered) { $covered += $block.Count }
}
if ($statements -eq 0) { throw 'カバレッジ対象がありません' }
$percent = 100.0 * $covered / $statements
Write-Output ('Statement coverage: {0:F2}% ({1}/{2})' -f $percent, $covered, $statements)
if ($covered * 100 -lt $statements * $Minimum) {
    throw "カバレッジが最低値 $Minimum% に達していません"
}
