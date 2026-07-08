# Hands-on — External Table JOIN

> 범위: **VNet Flow Logs**와 **Azure Firewall 로그**를 Blob Storage에 저장한 상태에서, Azure Data Explorer(ADX)의 **External Table 2개(파티션 적용) → 파싱 함수(뷰) → JOIN**까지 단계별로 구성한다.

## 사전 준비 (Prerequisite)

실습을 시작하기 전에 아래가 준비되어 있어야 한다. 핵심은 **VNet Flow Log와 Azure Firewall 로그가 같은(또는 접근 가능한) Storage 계정에 적재되고 있는 것**이다.

### 리소스와 권한

- **ADX 전용 클러스터** (Dev/Test 이상). 무료 클러스터는 External Table을 지원하지 않는다.
- **로그를 저장할 Storage 계정**(Blob).
- **권한**: 클러스터에 대한 Contributor(관리 ID·정책 설정), Storage에 RBAC 역할을 부여할 수 있는 권한(Owner 또는 User Access Administrator), 대상 리소스의 진단 설정을 변경할 수 있는 권한.
- **도구**: Azure Portal 또는 Azure CLI, ADX 웹 UI(dataexplorer.azure.com) 접근.

### VNet Flow Log를 Storage에 저장하도록 구성

가상 네트워크의 트래픽을 지정한 Storage 계정에 기록하도록 Flow Log를 활성화한다.

- **Portal:** Network Watcher → **Flow logs → Create** → Flow log type = **Virtual network** → 대상 리소스(VNet/서브넷/NIC) 선택 → **Storage 계정** 지정 → 저장. (Traffic Analytics는 선택)
- **CLI:**
  ```powershell
  az network watcher flow-log create `
    --name <flowlog-name> --resource-group <nw-rg> --location <region> `
    --vnet <vnet-name> --storage-account <storage> --enabled true
  ```
- 활성화되면 Storage 계정의 `insights-logs-flowlogflowevent` 컨테이너에 로그가 생성된다.

### Azure Firewall 로그를 Storage에 보관하도록 구성

방화벽의 네트워크 규칙 로그를 진단 설정으로 같은 Storage 계정에 보관한다.

- **Portal:** Azure Firewall → **Diagnostic settings → Add** → 로그 카테고리 **AZFWNetworkRule**(구조적) 선택 → **Archive to a storage account** → Storage 지정 → 저장.
- **CLI:**
  ```powershell
  $fwId = az network firewall show -n <firewall> -g <fw-rg> --query id -o tsv
  $storageId = az storage account show -n <storage> -g <storage-rg> --query id -o tsv
  az monitor diagnostic-settings create `
    --name fw-to-storage --resource $fwId --storage-account $storageId `
    --logs '[{\"category\":\"AZFWNetworkRule\",\"enabled\":true}]'
  ```
- 구조적(`AZFWNetworkRule`) 로그를 권장하며, 이 경우 파싱은 9.3 함수를 사용한다. 레거시(Azure diagnostics) 형식으로 보관되면 9.4 함수를 사용한다.

### 적재 확인

- 트래픽이 발생한 뒤 Storage 탐색기에서 해당 컨테이너에 blob이 생겼는지 확인한다. 로그는 수집·flush 지연(수 분)이 있다.
- blob 하나를 열어 실제 경로와 레코드 스키마(구조적/레거시)를 확인하고, 6·7단계의 `pathformat`·스키마에 반영한다.

> <span style="color:#1f6feb">**참고**</span> 두 로그를 서로 다른 Storage 계정에 두어도 됩니다. 이 경우 각 계정에 관리 ID 역할(4단계)을 부여하고 외부 테이블 연결 문자열을 각각의 계정으로 지정합니다.

## 1. Data Explorer 클러스터의 시스템 할당 관리 ID 활성화

외부 테이블이 Storage blob을 읽을 때 사용할 관리 ID를 먼저 만든다.

- **Portal:** ADX 클러스터 → **Security + networking → Identity → System assigned → Status = On → Save**. 생성된 **Object(principal) ID**를 복사해 둔다.
- **CLI:**
  ```powershell
  az kusto cluster update --name <cluster> --resource-group <cluster-rg> --type SystemAssigned
  # principalId 확인
  az kusto cluster show --name <cluster> --resource-group <cluster-rg> --query identity.principalId -o tsv
  ```

---

## 2. Data Explorer 데이터베이스 생성

외부 테이블·파싱 함수·쿼리는 모두 데이터베이스 안에 존재하므로, 클러스터에 데이터베이스가 최소 하나 있어야 한다. External Table만 사용하고 데이터를 ingest하지 않으므로 보존/캐시는 최소로 둔다.

- **Portal:** ADX 클러스터 → **Databases → Add database**
  - **Database name:** 예) `NetworkLogs`
  - **Retention period (days):** 낮게 설정(예: `7`)
  - **Cache period (days):** 낮게 설정(예: `1`)
  - **Create**
- **CLI:**
  ```powershell
  az kusto database create `
    --cluster-name <cluster> --resource-group <cluster-rg> `
    --database-name NetworkLogs `
    --read-write-database location="<region>" soft-delete-period="P7D" hot-cache-period="P1D"
  ```
  (`soft-delete-period`=보존, `hot-cache-period`=캐시. az 버전에 따라 파라미터 형태가 다를 수 있음)

External Table 데이터는 데이터베이스로 ingest되지 않고 쿼리 시 Blob에서 직접 읽으므로, 보존/캐시 정책은 외부 테이블 조회에 영향을 주지 않는다. 값을 낮게 두어 실수로 ingest될 때의 비용만 최소화한다.

> <span style="color:#1f6feb">**참고**</span> 이후 만드는 외부 테이블과 함수는 이 데이터베이스 안에 만들고, 모든 쿼리는 이 데이터베이스를 쿼리 컨텍스트로 선택해 실행한다. 무료 클러스터는 External Table을 지원하지 않으므로 Dev/Test 이상 전용 클러스터를 사용한다.

---

## 3. 내 계정을 `AllDatabasesAdmin`으로 추가

외부 테이블·함수 생성과 클러스터 정책 변경에 필요한 권한이다.

- **Portal:** ADX 클러스터 → **Security + networking → Permissions → Add → AllDatabasesAdmin →** 본인 계정(Entra) 선택 → Save.
- **CLI:**
  ```powershell
  az kusto cluster add-principal --cluster-name <cluster> --resource-group <cluster-rg> `
    --value principals-role="AllDatabasesAdmin" name="<you@contoso.com>" type="User"
  ```

---

## 4. 관리 ID에 Storage Blob Data Reader 역할 부여

`;managed_identity=system`으로 blob을 읽으려면 클러스터 관리 ID에 **Storage Blob Data Reader**(데이터 평면 읽기) 역할이 있어야 한다. Owner/Contributor(제어 평면)로는 blob 데이터에 접근할 수 없다.

```powershell
# 대상 Storage(로그 저장 계정) resource id
$storageId = az storage account show -n <storage> -g <storage-rg> --query id -o tsv
# 클러스터 관리 ID principalId (1단계에서 확인)
$miPrincipal = az kusto cluster show --name <cluster> --resource-group <cluster-rg> --query identity.principalId -o tsv
az role assignment create --assignee-object-id $miPrincipal --assignee-principal-type ServicePrincipal `
  --role "Storage Blob Data Reader" --scope $storageId
```

> <span style="color:#1f6feb">**참고**</span> 역할 전파에 수 분이 걸릴 수 있어 직후 쿼리가 실패하면 잠시 후 재시도한다. Storage에 방화벽/Private Endpoint가 걸려 있으면 신뢰할 수 있는 서비스 허용 또는 Managed Private Endpoint(blob) 구성이 추가로 필요하다.

---

## 5. Managed Identity 정책(`ExternalTable` usage) 설정

관리 ID 정책은 클러스터(또는 데이터베이스) 단위로 한 번 설정하면 그 범위의 모든 외부 테이블에 적용된다. 외부 테이블을 만들기 전에 설정해 둔다.

```kusto
.alter-merge cluster policy managed_identity ```[
    {
        "ObjectId": "system",
        "AllowedUsages": "ExternalTable"
    }
]```
```
- `ObjectId: "system"` = 시스템 할당 관리 ID, `AllowedUsages: "ExternalTable"` = 외부 테이블 접근에 이 ID 사용을 허용.
- 데이터베이스 단위로 제한하려면 `.alter-merge database <db> policy managed_identity ...` 를 사용한다.
- 확인: `.show cluster policy managed_identity`.

---

## 6. VNet Flow Log 외부 테이블 생성 (Partition by)

VNet Flow Logs의 blob 경로는 `flowLogResourceID=/{구독ID}_{RG}/{FlowLogName}/y=…` 형식이며, 첫 세그먼트 `{구독ID}_{RG}`는 `/` 구분이 없어 하나의 파티션 컬럼(`NetworkWatcherRG`)으로 잡는다.

경로 예: `insights-logs-flowlogflowevent/flowLogResourceID=/B0D432B7-…-255DF_NETWORKWATCHERRG/NETWORKWATCHER_EASTUS_VNET-EUS-COMMON-RG-COMMON-FLOWLOG/y=2026/m=07/d=07/h=15/m=00/macAddress=…/PT1H.json`

```kusto
.create-or-alter external table ExternalVNetFlowLogs (records: dynamic)
kind = blob
partition by (NetworkWatcherRG:string, FlowLogName:string, Timestamp:datetime)
pathformat = (
    "flowLogResourceID=/" NetworkWatcherRG
    "/" FlowLogName
    "/y=" datetime_pattern("yyyy'/m='MM'/d='dd'/h='HH", Timestamp)
)
dataformat = multijson
(
    h@"https://<storage>.blob.core.windows.net/insights-logs-flowlogflowevent;managed_identity=system"
)
```

| 파티션 가상 컬럼 | 경로 세그먼트 | 예시값 · 용도 |
| --- | --- | --- |
| `NetworkWatcherRG` | `flowLogResourceID=/<val>/` | `B0D432B7-…-255DF_NETWORKWATCHERRG` — **`{구독ID}_{RG}` 단일 세그먼트** |
| `FlowLogName` | `/<val>/` | `NETWORKWATCHER_EASTUS_VNET-EUS-COMMON-RG-COMMON-FLOWLOG` — Flow Log 리소스명 |
| `Timestamp` | `/y=YYYY/m=MM/d=DD/h=HH` | **시간 프루닝(가장 중요)** |

- `datetime_pattern("yyyy'/m='MM'/d='dd'/h='HH", Timestamp)` → `2026/m=07/d=07/h=15`, 앞의 `"/y="`와 합쳐 `/y=2026/m=07/d=07/h=15`.
- 경로 뒤 `/m=00/macAddress=…/PT1H.json`는 파티션 이후 자동 스캔 대상이라 pathformat에 넣지 않는다.
- 구독만 좁히려면 `where NetworkWatcherRG startswith "<구독ID>"`, 여러 Flow Log는 `FlowLogName`으로 구분·프루닝한다.

> <span style="color:#c00000">**주의**</span> 경로 세그먼트가 모두 대문자이므로 파티션 컬럼 필터도 대소문자를 구분한다.

---

## 7. Firewall Log 외부 테이블 생성 (Partition by)

방화벽 로그는 전체 ARM 리소스 ID 경로를 사용하며(방화벽은 `macAddress` 세그먼트 없음), blob 내용은 **NDJSON(줄마다 레코드 1개)** 이고 `{"records":[…]}` 래퍼가 없다. 따라서 외부 테이블 스키마는 `(records:dynamic)`이 아니라 레코드의 최상위 필드로 정의한다.

경로 예: `insights-logs-azurefirewall/resourceId=/SUBSCRIPTIONS/…/AZUREFIREWALLS/AZUREFIREWALL_VHUB-P-SALES-EUS/y=2026/m=07/d=07/h=14/m=00/PT1H.json`

> <span style="color:#c00000">**주의**</span> 이 컨테이너에는 구조적 로그(`category:"AZFWNetworkRule"`, `properties`에 SourceIp·DestinationIp 등)와 레거시 로그(`category:"AzureFirewallNetworkRule"`, `properties.msg` 문자열)가 함께 들어올 수 있다. 파싱 함수에서 `category`로 구분한다(구조적 §9.3, 레거시 §9.4).

```kusto
.create-or-alter external table ExternalFirewallLogs (
    ['time']: datetime,
    resourceId: string,
    operationName: string,
    category: string,
    properties: dynamic
)
kind = blob
partition by (SubscriptionId:string, FirewallRG:string, FirewallName:string, Timestamp:datetime)
pathformat = (
    "resourceId=/SUBSCRIPTIONS/" SubscriptionId
    "/RESOURCEGROUPS/" FirewallRG
    "/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/" FirewallName
    "/y=" datetime_pattern("yyyy'/m='MM'/d='dd'/h='HH", Timestamp)
)
dataformat = multijson
(
    h@"https://<storage>.blob.core.windows.net/insights-logs-azurefirewall;managed_identity=system"
)
```

- 컬럼명은 JSON 필드명과 대소문자까지 정확히 맞추다: `time`·`resourceId`·`operationName`·`category`·`properties`. `properties`는 `dynamic`으로 담아 함수에서 펼친다. `time`은 `['time']`로 표기한다.

| 파티션 가상 컬럼 | 경로 세그먼트 | 예시값 |
| --- | --- | --- |
| `SubscriptionId` | `.../SUBSCRIPTIONS/<val>/...` | `B0D432B7-C234-4614-8B3D-E8D1B12255DF` |
| `FirewallRG` | `.../RESOURCEGROUPS/<val>/...` | `RG-CORE` |
| `FirewallName` | `.../AZUREFIREWALLS/<val>/...` | `AZUREFIREWALL_VHUB-P-SALES-EUS` |
| `Timestamp` | `.../y=YYYY/m=MM/d=DD/h=HH` | 시간 프루닝(레코드 `time`은 초 단위 정밀) |

- 관리 ID 정책은 5단계에서 클러스터 전체에 적용되어 이 테이블에도 유효하다(별도 작업 불필요).
- 동일 이벤트가 구조적·레거시로 중복 기록될 수 있으므로, 구조적만 쓰려면 `category == "AZFWNetworkRule"`로 필터한다(§9.3에 포함).

---

## 8. 각 외부 테이블 쿼리 테스트

정의가 blob에 정상 매핑되는지, 파티션 프루닝이 동작하는지 확인한다.

```kusto
external_table("ExternalVNetFlowLogs")
| where Timestamp > ago(2h)
| take 3

external_table("ExternalFirewallLogs")
| where Timestamp > ago(2h)
| take 3

external_table("ExternalVNetFlowLogs") | where Timestamp > ago(1h) | count
```

**기대 결과:** 각 테이블에서 행이 반환된다. `Forbidden` 오류가 나면 4·5단계(역할·정책)를 다시 확인한다.

> <span style="color:#1f6feb">**참고**</span> `.show queries` 등으로 스캔한 blob 범위를 보면 `Timestamp` 필터 유무에 따라 스캔량이 달라지는 것을 확인할 수 있다.

---

## 9. 파싱 함수(뷰) 생성

각 외부 테이블을 행·열로 펼치는 저장 함수를 만든다. 파티션 컬럼 `Timestamp`를 그대로 노출해 함수를 통해 조회할 때도 프루닝이 유지되게 한다.

### 9.1 프로토콜 정규화 헬퍼

Flow Log의 프로토콜은 숫자, 방화벽 로그는 문자열이므로 아래 VNet 뷰(§9.2)에서 이 헬퍼로 숫자를 문자열로 변환해 맞춘다.
```kusto
.create-or-alter function ProtoName(p:string) {
    case(p == "6", "TCP", p == "17", "UDP", p == "1", "ICMP", p)
}
```

### 9.2 VNet Flow Logs 뷰
```kusto
.create-or-alter function with (docstring = "View: Parsed VNet Flow Logs", folder = "NetworkLogs")
ParsedVNetFlowLogs() {
    external_table("ExternalVNetFlowLogs")
    | mv-expand Record = records
    | project Timestamp,                                   // 파티션 통과(프루닝)
              Time = todatetime(Record['time']),
              TargetResourceID = tostring(Record.targetResourceID),
              Flows = Record.flowRecords.flows
    | mv-expand Flow = Flows
    | project Timestamp, Time, TargetResourceID,
              AclID = tostring(Flow.aclID), FlowGroups = Flow.flowGroups
    | mv-expand FlowGroup = FlowGroups
    | project Timestamp, Time, TargetResourceID, AclID,
              Rule = tostring(FlowGroup.rule), FlowTuples = FlowGroup.flowTuples
    | mv-expand FlowTuple = FlowTuples
    | extend T = split(tostring(FlowTuple), ",")
    | where array_length(T) == 13                          // 버전 가드
    | project Timestamp, Time, TargetResourceID, AclID, Rule,
              SrcIP = tostring(T[1]),  DstIP = tostring(T[2]),
              SrcPort = toint(T[3]),   DstPort = toint(T[4]),
              Protocol = ProtoName(tostring(T[5])),         // 뷰에서 TCP/UDP로 정규화
              FlowDirection = tostring(T[6]),
              FlowState = tostring(T[7]),
              FlowEncryption = tostring(T[8]),              // 인덱스 8 = 암호화 상태(X/NX)
              PacketsSrcToDst = tolong(T[9]),  BytesSrcToDst = tolong(T[10]),
              PacketsDstToSrc = tolong(T[11]), BytesDstToSrc = tolong(T[12])
}
```
중첩 배열을 `mv-expand`로 행 단위로 펼치고 `split()`으로 튜플을 열로 분리한다. `FlowState == "D"`는 거부(Deny)를 뜻한다.

### 9.3 Firewall 로그 뷰 (구조적 `AZFWNetworkRule`)
```kusto
.create-or-alter function with (docstring = "View: Parsed Azure Firewall Network Rule logs", folder = "NetworkLogs")
ParsedFirewallNetworkRule() {
    external_table("ExternalFirewallLogs")
    | where category == "AZFWNetworkRule"                   // 구조적 레코드만(레거시 category 제외)
    | project
        Timestamp,                                          // 파티션 통과(프루닝)
        Time                = todatetime(['time']),
        ResourceId          = tostring(resourceId),
        SourceIp            = tostring(properties.SourceIp),
        SourcePort          = toint(properties.SourcePort),
        DestinationIp       = tostring(properties.DestinationIp),
        DestinationPort     = toint(properties.DestinationPort),
        FwProtocol          = tostring(properties.Protocol),   // "TCP"/"UDP"
        Action              = tostring(properties.Action),     // "Allow"/"Deny"
        Policy              = tostring(properties.Policy),
        RuleCollectionGroup = tostring(properties.RuleCollectionGroup),
        RuleCollection      = tostring(properties.RuleCollection),
        FwRule              = tostring(properties.Rule)
}
```
blob이 NDJSON이므로 `mv-expand records` 없이 레코드 컬럼을 직접 참조한다.

### 9.4 Firewall 로그 뷰 — 레거시(msg 기반)

로그가 레거시 형식(`category:"AzureFirewallNetworkRule"`, `properties.msg` 문자열)일 때 사용한다. `parse`로 msg에서 필드를 추출한다.

```kusto
.create-or-alter function with (docstring = "View: Parsed legacy Azure Firewall Network Rule (msg 기반)", folder = "NetworkLogs")
ParsedFirewallNetworkRuleLegacy() {
    external_table("ExternalFirewallLogs")
    | where category == "AzureFirewallNetworkRule"          // 레거시 category
    | extend msg = tostring(properties.msg)
    | parse msg with FwProtocol " request from " SourceIp ":" SourcePort:int
            " to " DestinationIp ":" DestinationPort:int ". Action: " Action
            ".. Policy: " Policy ". Rule Collection Group: " RuleCollectionGroup
            ". Rule Collection: " RuleCollection ". Rule: " FwRule
    | project Timestamp,                                   // 파티션 통과(프루닝)
              Time = todatetime(['time']), ResourceId = tostring(resourceId),
              FwProtocol, SourceIp, SourcePort, DestinationIp, DestinationPort,
              Action, Policy, RuleCollectionGroup, RuleCollection, FwRule, msg
}
```
msg 예: `"TCP request from 10.64.200.4:54218 to 20.10.127.192:443. Action: Allow.. Policy: fwp-p-sales. Rule Collection Group: … Rule Collection: … Rule: AllowAny"` (Action 뒤 점 2개 주의).

> <span style="color:#c00000">**주의**</span> msg 형식은 규칙 매칭 여부에 따라 달라진다. 미매칭·Deny 등에서는 뒤 절이 없거나 `Reason:`이 붙을 수 있으므로 실제 msg에 맞추어 `parse` 패턴을 조정한다. 이 함수는 §9.3과 동일한 핵심 컬럼명을 노출하므로, 조인에서 함수명만 교체하면 된다.

---

## 10. 각 함수 쿼리 테스트

```kusto
ParsedVNetFlowLogs()
| where Timestamp > ago(1h)
| take 20

ParsedFirewallNetworkRule()
| where Timestamp > ago(1h)
| take 20
```

**기대 결과:** 평탄화된 행·열 형태로 결과가 반환된다.

---

## 11. JOIN 테스트

두 외부 테이블을 5-tuple + 1분 시간 윈도우로 조인해, 하나의 통신을 네트워크 flow(전송량)와 방화벽 규칙(정책 근거) 두 관점에서 함께 살펴본다.

```kusto
let t0 = ago(1h);
// 네트워크 flow: outbound 세션의 전송량
let flows =
    ParsedVNetFlowLogs()
    | where Timestamp between (t0 .. now())
    | where Protocol == "TCP" and FlowDirection == "O"
    | summarize Bytes = sum(BytesSrcToDst + BytesDstToSrc)
        by SrcIP, DstIP, DstPort, Min = bin(Time, 1m);
// 방화벽: 규칙 평가 결과
let fw =
    ParsedFirewallNetworkRule()
    | where Timestamp between (t0 .. now())
    | where FwProtocol == "TCP"
    | summarize Hits = count(), Actions = make_set(Action)
        by SourceIp, DestinationIp, DestinationPort, Policy, RuleCollection, FwRule, Min = bin(Time, 1m);
flows
| join kind=inner fw on
      $left.SrcIP == $right.SourceIp,
      $left.DstIP == $right.DestinationIp,
      $left.DstPort == $right.DestinationPort,
      $left.Min == $right.Min
| project Min, SrcIP, DstIP, DstPort,
          FwRule, RuleCollection, Policy, Actions,
          MB = round(Bytes / 1048576.0, 1)
| order by Min asc
```

**기대 결과:** 각 통신이 어느 방화벽 규칙으로 허용/거부되었고(방화벽) 그 구간에 몇 MB가 흘렀는지(flow)를 한 행에서 확인한다.

> <span style="color:#c00000">**주의**</span> ① Flow의 프로토콜은 §9.2 뷰에서 이미 `ProtoName()`으로 정규화되어 방화벽의 문자열과 바로 비교된다. ② 클라이언트 소스 포트는 연결마다 달라지므로 조인 키에서 제외하고 목적 포트를 사용한다. ③ 방화벽이 사설 목적지를 SNAT하면 SourceIp가 바뀌어 5-tuple 조인이 어긋난다. ④ 방화벽 로그가 레거시(msg 기반)이면 `ParsedFirewallNetworkRule()`를 `ParsedFirewallNetworkRuleLegacy()`(§9.4)로 교체한다.

---

## 12. 확인 사항

- 파티션 경로(§6·§7)와 대소문자가 대상 환경의 실제 blob 경로와 일치하는지 확인한다.
- 방화벽 로그가 구조적(`AZFWNetworkRule`)인지 레거시(`AzureFirewallNetworkRule`, msg)인지에 따라 §9.3 또는 §9.4 함수를 선택한다.
- 여러 팀이 공유하는 클러스터라면 관리 ID 정책을 데이터베이스 단위로 제한한다.

## FAQ

실습 단계별 예상 질문과 답변은 별도 문서 [hands-on-firewall-flowlog-join-faq.md](hands-on-firewall-flowlog-join-faq.md)에 정리되어 있다.

## 참고 자료

- Microsoft Learn — Authenticate external tables with managed identities: https://learn.microsoft.com/azure/data-explorer/external-tables-managed-identities
- Microsoft Learn — Configure managed identities for your Azure Data Explorer cluster: https://learn.microsoft.com/azure/data-explorer/configure-managed-identities-cluster
- Microsoft Learn — Create and alter Azure Storage external tables: https://learn.microsoft.com/kusto/management/external-tables-azurestorage-azuredatalake
- Microsoft Learn — AZFWNetworkRule table / Monitoring data reference for Azure Firewall: https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwnetworkrule
